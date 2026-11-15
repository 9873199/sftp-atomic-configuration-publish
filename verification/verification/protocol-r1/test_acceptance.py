"""Independent reviewer protocol cases, never installed into the model artifact."""
import asyncio,hashlib,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import asyncssh
from asyncssh.sftp import SFTPServerHandler,FXF_EXCL

class Stream:
 def __init__(self,data,short=3,error=None):self.data=data;self.pos=0;self.short=short;self.sizes=[];self.error=error
 async def read(self,n):
  self.sizes.append(n)
  if self.error and self.pos>=3:raise self.error
  out=self.data[self.pos:self.pos+min(n,self.short)];self.pos+=len(out);return out
class Auth(asyncssh.SSHServer):
 def __init__(self,key):self.key=key
 def begin_auth(self,user):return True
 def public_key_auth_supported(self):return True
 def validate_public_key(self,user,key):return key.export_public_key()==self.key.export_public_key()
class Server(asyncssh.SFTPServer):
 def __init__(self,chan,owner):super().__init__(chan,str(owner.root));self.o=owner
 def open(self,path,flags,attrs):self.o.events.append(('open',path,flags));return super().open(path,flags,attrs)
 async def write(self,handle,offset,data):
  self.o.events.append(('write',offset,len(data)));self.o.assertEqual((self.o.root/'cfg').read_bytes(),b'old')
  if self.o.mode=='write-wait':self.o.entered.set();await self.o.release.wait()
  if self.o.mode=='write-error':await asyncio.sleep(.03);raise asyncssh.SFTPFailure('review-write-error')
  return super().write(handle,offset,data)
 async def close(self,handle):
  self.o.events.append(('close',));out=super().close(handle)
  if self.o.mode=='close-wait':self.o.entered.set();await self.o.release.wait()
  if self.o.mode in ('close-error','cleanup-errors'):raise asyncssh.SFTPFailure('review-close-error')
  return out
 def remove(self,path):
  self.o.events.append(('remove',path))
  if self.o.mode=='cleanup-errors':raise asyncssh.SFTPFailure('review-remove-error')
  return super().remove(path)
 async def posix_rename(self,old,new):
  self.o.events.append(('rename',old,new))
  if self.o.mode=='rename-reject':raise asyncssh.SFTPPermissionDenied('review-rename-reject')
  if self.o.mode=='drop-before':self.connection.abort();return
  out=super().posix_rename(old,new)
  if self.o.mode=='drop-after':self.connection.abort()
  return out
class PublishProtocol(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='sftp-review-');self.root=Path(self.tmp.name);(self.root/'cfg').write_bytes(b'old');self.events=[];self.mode='';self.entered=asyncio.Event();self.release=asyncio.Event();self.key=asyncssh.generate_private_key('ssh-ed25519');host=asyncssh.generate_private_key('ssh-ed25519')
  self.listener=await asyncssh.listen('127.0.0.1',0,server_factory=lambda:Auth(self.key),server_host_keys=[host],sftp_factory=lambda chan:Server(chan,self),config=[])
  self.conn=await asyncssh.connect('127.0.0.1',self.listener.get_port(),client_keys=[self.key],known_hosts=None,config=[],agent_path=None);self.sftp=await self.conn.start_sftp_client()
 async def asyncTearDown(self):
  self.release.set();self.sftp.exit();await self.sftp.wait_closed();self.conn.close();await self.conn.wait_closed();self.listener.close();await self.listener.wait_closed();self.tmp.cleanup()
 def names(self,kind):return [e for e in self.events if e[0]==kind]
 def assert_old_clean(self):self.assertEqual((self.root/'cfg').read_bytes(),b'old');self.assertEqual(sorted(p.name for p in self.root.iterdir()),['cfg']);self.assertFalse(self.names('rename'))
 async def send(self,data=b'abcdefghijk',size=None,digest=None,stream=None):
  return await self.sftp.publish(stream or Stream(data),'cfg',len(data) if size is None else size,hashlib.sha256(data).hexdigest() if digest is None else digest,block_size=4)
 async def test_short_reads_and_ack_order(self):
  data=bytes(range(256))*8;s=Stream(data,1);await self.send(data,stream=s);self.assertEqual((self.root/'cfg').read_bytes(),data);self.assertEqual(len(self.names('rename')),1);self.assertTrue(all(0<n<=4 for n in s.sizes));self.assertTrue(all(e[2]<=4 for e in self.names('write')));self.assertEqual(len(self.names('close')),1);self.assertLess(next(i for i,e in enumerate(self.events) if e[0]=='close'),next(i for i,e in enumerate(self.events) if e[0]=='rename'));self.assertFalse(self.names('remove'));self.assertTrue(self.names('open')[0][2]&FXF_EXCL)
 async def test_empty_stream(self):await self.send(b'');self.assertEqual((self.root/'cfg').read_bytes(),b'')
 async def test_wrong_digest(self):
  with self.assertRaises(asyncssh.SFTPFailure):await self.send(digest='00'*32)
  self.assert_old_clean()
 async def test_short_length(self):
  with self.assertRaises(asyncssh.SFTPFailure):await self.send(size=12)
  self.assert_old_clean()
 async def test_excess_length(self):
  with self.assertRaises(asyncssh.SFTPFailure):await self.send(size=3)
  self.assert_old_clean()
 async def test_source_error_identity(self):
  err=RuntimeError('review-source-error')
  with self.assertRaises(RuntimeError) as got:await self.send(stream=Stream(b'abcdefghijkl',error=err))
  self.assertIs(got.exception,err);self.assert_old_clean()
 async def test_delayed_write_rejected(self):
  self.mode='write-error'
  with self.assertRaises(asyncssh.SFTPFailure):await self.send()
  self.assert_old_clean();self.assertTrue(self.names('close'))
 async def test_close_rejected(self):
  self.mode='close-error'
  with self.assertRaises(asyncssh.SFTPFailure):await self.send()
  self.assert_old_clean()
 async def cancel_at(self,mode):
  self.mode=mode;task=asyncio.create_task(self.send());await asyncio.wait_for(self.entered.wait(),3);task.cancel('review-cancel')
  try:
   with self.assertRaises(asyncio.CancelledError) as got:await asyncio.wait_for(task,3)
   self.assertEqual(got.exception.args,('review-cancel',));self.assertTrue(task.cancelled());self.assert_old_clean()
  finally:self.release.set()
 async def test_cancel_write_pending_ack(self):await self.cancel_at('write-wait')
 async def test_cancel_close_pending_ack(self):await self.cancel_at('close-wait')
 async def test_collision_preserves_foreign_file(self):
  (self.root/'foreign').write_bytes(b'owner-data')
  with patch('asyncssh.sftp._publish_temp_name',side_effect=[b'foreign',b'owned-temp']):await self.send()
  self.assertEqual((self.root/'foreign').read_bytes(),b'owner-data');self.assertEqual((self.root/'cfg').read_bytes(),b'abcdefghijk');self.assertEqual(len(self.names('open')),2);self.assertFalse(self.names('remove'));self.assertEqual(self.names('rename')[0][1],b'owned-temp')
 async def test_extension_unavailable_no_write(self):
  self.sftp.exit();await self.sftp.wait_closed();ext=[x for x in SFTPServerHandler._extensions if x[0]!=b'posix-rename@openssh.com']
  with patch.object(SFTPServerHandler,'_extensions',ext):self.sftp=await self.conn.start_sftp_client()
  self.events.clear()
  with self.assertRaises(asyncssh.SFTPOpUnsupported):await self.send()
  self.assertEqual(self.events,[]);self.assert_old_clean()
 async def test_rename_rejected(self):
  self.mode='rename-reject'
  with self.assertRaises(asyncssh.SFTPPermissionDenied):await self.send()
  self.assertEqual((self.root/'cfg').read_bytes(),b'old');self.assertEqual(len(self.names('rename')),1);self.assertEqual(sorted(p.name for p in self.root.iterdir()),['cfg']);self.assertTrue(self.names('remove'))
 async def lost_response(self,mode,expected):
  self.mode=mode
  with self.assertRaises(asyncssh.SFTPPublishUnknown):await self.send()
  self.assertEqual((self.root/'cfg').read_bytes(),expected);self.assertEqual(len(self.names('rename')),1);self.assertFalse(self.names('remove'))
 async def test_response_lost_before_replace(self):await self.lost_response('drop-before',b'old')
 async def test_response_lost_after_replace(self):await self.lost_response('drop-after',b'abcdefghijk')
 async def test_cleanup_errors_keep_original(self):
  self.mode='cleanup-errors';err=ValueError('original-source-error')
  with self.assertRaises(ValueError) as got:await self.send(stream=Stream(b'abcdefghijkl',error=err))
  self.assertIs(got.exception,err);notes=' '.join(getattr(err,'__notes__',[]));self.assertIn('review-close-error',notes);self.assertIn('review-remove-error',notes);self.assertEqual((self.root/'cfg').read_bytes(),b'old');self.assertFalse(self.names('rename'))
 async def test_invalid_arguments_no_protocol(self):
  for kw in ({'size':-1},{'digest':'00'}):
   with self.assertRaises(ValueError):await self.send(**kw)
  self.assertEqual(self.events,[])
if __name__=='__main__':unittest.main(verbosity=2)
