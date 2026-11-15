# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for atomic SFTP publish

   These tests run a temporary AsyncSSH/SFTP server bound only to the
   loopback address, using keys generated for the test run. They never
   connect to a pre-existing SSH service or read personal known_hosts
   or private key files.

"""

import asyncio
import errno
import hashlib
import os
import unittest
from unittest.mock import patch

import asyncssh

from asyncssh import SFTPFailure, SFTPOpUnsupported, SFTPPublishUnknown
from asyncssh.sftp import SFTPServerHandler

from .util import AsyncTestCase, asynctest


_TEMP_PREFIX = '.asyncssh-publish-'


class _ByteStream:
    """A read-only async byte stream which only supports read()"""

    def __init__(self, data, chunk_size=5, on_read=None):
        self._data = data
        self._chunk_size = chunk_size
        self._on_read = on_read
        self._pos = 0

    async def read(self, size):
        """Return at most chunk_size bytes, forcing short reads"""

        if self._pos >= len(self._data):
            return b''

        end = min(self._pos + min(size, self._chunk_size), len(self._data))
        block = self._data[self._pos:end]
        self._pos = end

        if self._on_read:
            self._on_read(self._pos)

        return block


class _SSHServer(asyncssh.SSHServer):
    """SSH server which accepts only the test run's client key"""

    def __init__(self, ckey):
        self._ckey = ckey

    def begin_auth(self, username):
        """Require public key authentication"""

        return True

    def public_key_auth_supported(self):
        """Support public key authentication"""

        return True

    def validate_public_key(self, username, key):
        """Accept only the client key generated for this test run"""

        return key.export_public_key() == self._ckey.export_public_key()


class _PublishSFTPServer(asyncssh.SFTPServer):
    """SFTP server which records requests and injects faults"""

    def __init__(self, chan, chroot, events, faults):
        super().__init__(chan, chroot)

        self._events = events
        self._faults = faults

    def open(self, path, pflags, attrs):
        """Record an open request"""

        self._events.append(('open', path))
        return super().open(path, pflags, attrs)

    async def write(self, file_obj, offset, data):
        """Record a write, optionally failing after a delay"""

        self._events.append(('write', offset, len(data)))

        fail_at = self._faults.get('fail_write_at')

        if fail_at is not None and offset >= fail_at:
            await asyncio.sleep(self._faults.get('write_delay', 0.1))
            raise OSError(errno.EIO, 'Injected write failure')

        return super().write(file_obj, offset, data)

    def close(self, file_obj):
        """Record a close, optionally failing it"""

        self._events.append(('close',))

        result = super().close(file_obj)

        if self._faults.get('fail_close'):
            raise OSError(errno.EIO, 'Injected close failure')

        return result

    def remove(self, path):
        """Record a remove request"""

        self._events.append(('remove', path))
        return super().remove(path)

    async def posix_rename(self, oldpath, newpath):
        """Record a rename, optionally dropping the connection after it"""

        self._events.append(('posix_rename', oldpath, newpath))

        super().posix_rename(oldpath, newpath)

        if self._faults.get('drop_on_rename'):
            # Drop the connection without sending a response, leaving
            # the client unable to determine the publish result
            self.connection.abort()


class _TestSFTPPublish(AsyncTestCase):
    """Unit tests for SFTPClient.publish"""

    @classmethod
    async def asyncSetUpClass(cls):
        """Generate keys for this test run"""

        cls._ckey = asyncssh.generate_private_key('ssh-ed25519')
        cls._skey = asyncssh.generate_private_key('ssh-ed25519')

    async def asyncSetUp(self):
        """Start a loopback-only SSH/SFTP server for this test"""

        self._events = []
        self._faults = {}
        self._root = os.path.join(os.getcwd(),
                                  'remote-' + self._testMethodName)
        os.mkdir(self._root)

        def sftp_factory(chan):
            return _PublishSFTPServer(chan, self._root,
                                      self._events, self._faults)

        self._listener = await asyncssh.listen(
            '127.0.0.1', 0, server_factory=lambda: _SSHServer(self._ckey),
            server_host_keys=[self._skey], sftp_factory=sftp_factory)

        self._port = self._listener.get_port()

    async def asyncTearDown(self):
        """Shut down this test's listener"""

        self._listener.close()
        await self._listener.wait_closed()

    def _connect(self):
        """Open a connection to this test's server"""

        return asyncssh.connect('127.0.0.1', self._port,
                                client_keys=[self._ckey], known_hosts=None,
                                config=[], agent_path=None)

    def _temp_files(self):
        """Return leftover publish temporary files in the remote root"""

        return [name for name in os.listdir(self._root)
                if name.startswith(_TEMP_PREFIX)]

    def _read_remote(self, name):
        """Read a file in the remote root"""

        with open(os.path.join(self._root, name), 'rb') as local_file:
            return local_file.read()

    def _write_remote(self, name, data):
        """Write a file in the remote root"""

        with open(os.path.join(self._root, name), 'wb') as local_file:
            local_file.write(data)

    def _removes(self):
        """Return the paths of all recorded remove requests"""

        return [event[1] for event in self._events if event[0] == 'remove']

    def _renames(self):
        """Return all recorded posix_rename requests"""

        return [(event[1], event[2]) for event in self._events
                if event[0] == 'posix_rename']

    @asynctest
    async def test_publish(self):
        """Test atomically publishing a stream over an existing file"""

        old_data = b'old contents'
        data = bytes((7*i + 3) % 256 for i in range(300))

        self._write_remote('config.txt', old_data)

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.publish(_ByteStream(data), '/config.txt',
                                   len(data), hashlib.sha256(data).hexdigest(),
                                   block_size=64)

        # The target was atomically replaced with the new contents
        self.assertEqual(self._read_remote('config.txt'), data)

        # No temporary files were left behind
        self.assertEqual(self._temp_files(), [])

        # Exactly one atomic rename replaced the target, from a
        # temporary name in the same directory
        renames = self._renames()
        self.assertEqual(len(renames), 1)
        self.assertEqual(renames[0][1], b'/config.txt')
        self.assertTrue(renames[0][0].startswith(
            b'/' + _TEMP_PREFIX.encode('ascii')))

        # The target itself was never removed
        self.assertNotIn(b'/config.txt', self._removes())

    @asynctest
    async def test_publish_new_file(self):
        """Test publishing a stream to a path which doesn't exist yet"""

        data = bytes((5*i + 1) % 256 for i in range(200))

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.publish(_ByteStream(data), '/new.txt', len(data),
                                   hashlib.sha256(data).digest(),
                                   block_size=64)

        self.assertEqual(self._read_remote('new.txt'), data)
        self.assertEqual(self._temp_files(), [])

    @asynctest
    async def test_publish_empty(self):
        """Test publishing an empty stream"""

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.publish(_ByteStream(b''), '/empty.txt', 0,
                                   hashlib.sha256(b'').hexdigest())

        self.assertEqual(self._read_remote('empty.txt'), b'')
        self.assertEqual(self._temp_files(), [])

    @asynctest
    async def test_publish_short_data(self):
        """Test a stream which produces less data than expected"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPFailure):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data) + 1,
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        # The original file is untouched and the temp file is gone
        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])

    @asynctest
    async def test_publish_excess_data(self):
        """Test a stream which produces more data than expected"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPFailure):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data) - 1,
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])

    @asynctest
    async def test_publish_digest_mismatch(self):
        """Test a stream whose contents don't match the expected digest"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPFailure):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data),
                                       hashlib.sha256(b'').hexdigest(),
                                       block_size=64)

        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])

    @asynctest
    async def test_publish_cancel(self):
        """Test cancelling a publish in the middle of a write"""

        old_data = b'old contents'
        data = bytes((3*i + 1) % 256 for i in range(200))

        self._write_remote('config.txt', old_data)

        holder = {}

        def on_read(pos):
            task = holder.get('task')

            # Cancel once the first block has been written and the
            # publish is about to write the next one
            if task is not None and pos >= 100:
                task.cancel()

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                task = asyncio.ensure_future(
                    sftp.publish(_ByteStream(data, on_read=on_read),
                                 '/config.txt', len(data),
                                 hashlib.sha256(data).hexdigest(),
                                 block_size=64))
                holder['task'] = task

                with self.assertRaises(asyncio.CancelledError):
                    await task

                self.assertTrue(task.cancelled())

        # The original file is untouched and the temp file was removed
        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])

        # Only the temporary file was removed, never the target
        self.assertNotIn(b'/config.txt', self._removes())
        self.assertEqual(len(self._removes()), 1)

    @asynctest
    async def test_publish_write_failure(self):
        """Test a delayed write failure during a publish"""

        old_data = b'old contents'
        data = bytes((3*i + 2) % 256 for i in range(200))

        self._write_remote('config.txt', old_data)
        self._faults['fail_write_at'] = 64

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPFailure):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data),
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])
        self.assertNotIn(b'/config.txt', self._removes())

    @asynctest
    async def test_publish_close_failure(self):
        """Test a close failure at the end of a publish"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)
        self._faults['fail_close'] = True

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPFailure):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data),
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._renames(), [])
        self.assertNotIn(b'/config.txt', self._removes())

    @asynctest
    async def test_publish_unsupported(self):
        """Test publish against a server without POSIX rename support"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)

        extensions = [(name, data_) for name, data_ in
                      SFTPServerHandler._extensions
                      if name != b'posix-rename@openssh.com']

        with patch.object(SFTPServerHandler, '_extensions', extensions):
            async with self._connect() as conn:
                async with conn.start_sftp_client() as sftp:
                    with self.assertRaises(SFTPOpUnsupported):
                        await sftp.publish(_ByteStream(data), '/config.txt',
                                           len(data),
                                           hashlib.sha256(data).hexdigest())

        # Nothing was created, renamed, or removed
        self.assertEqual(self._read_remote('config.txt'), old_data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(self._events, [])

    @asynctest
    async def test_publish_name_collision(self):
        """Test a temporary name collision with someone else's file"""

        old_data = b'old contents'
        other_data = b'someone else'
        data = bytes(range(100))

        collision = _TEMP_PREFIX + '0123456789abcdef'

        self._write_remote('config.txt', old_data)
        self._write_remote(collision, other_data)

        names = [collision.encode('ascii')]

        def next_name():
            return names.pop(0) if names else orig_temp_name()

        orig_temp_name = asyncssh.sftp._publish_temp_name

        with patch('asyncssh.sftp._publish_temp_name', side_effect=next_name):
            async with self._connect() as conn:
                async with conn.start_sftp_client() as sftp:
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data),
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        # The publish retried with a fresh name and succeeded
        self.assertEqual(self._read_remote('config.txt'), data)

        # The colliding file belonging to someone else is untouched,
        # and no temporary files of our own were left behind
        self.assertEqual(self._read_remote(collision), other_data)
        self.assertEqual(self._temp_files(), [collision])

    @asynctest
    async def test_publish_response_lost(self):
        """Test the connection dropping after the rename was sent"""

        old_data = b'old contents'
        data = bytes(range(100))

        self._write_remote('config.txt', old_data)
        self._faults['drop_on_rename'] = True

        async with self._connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertRaises(SFTPPublishUnknown):
                    await sftp.publish(_ByteStream(data), '/config.txt',
                                       len(data),
                                       hashlib.sha256(data).hexdigest(),
                                       block_size=64)

        # The rename actually happened server-side, and the client
        # didn't mistake this for a failure: it didn't retry the
        # rename, remove the replaced target, or remove anything else
        self.assertEqual(self._read_remote('config.txt'), data)
        self.assertEqual(self._temp_files(), [])
        self.assertEqual(len(self._renames()), 1)
        self.assertEqual(self._removes(), [])


if __name__ == '__main__':
    unittest.main()
