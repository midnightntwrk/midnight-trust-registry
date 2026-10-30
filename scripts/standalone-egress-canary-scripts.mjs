export const canaryPort = 45987;
export const dnsCanaryName = "tr-offline-canary.invalid";
export const dnsCanaryAddress = "198.51.100.7";

export const apiEgressCanaryServerScript = String.raw`const net=require('node:net'),dgram=require('node:dgram');
net.createServer(socket=>socket.end('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')).listen(${canaryPort},'0.0.0.0');
const server=dgram.createSocket('udp4');
server.on('message',(query,remote)=>{
  if(query.length<18)return;
  let offset=12;const labels=[];
  while(offset<query.length&&query[offset]!==0){
    const length=query[offset++];if(length>63||offset+length>query.length)return;
    labels.push(query.subarray(offset,offset+length).toString('ascii'));offset+=length;
  }
  if(offset+5>query.length||labels.join('.')!=='${dnsCanaryName}'
    ||query.readUInt16BE(offset+1)!==1||query.readUInt16BE(offset+3)!==1)return;
  console.log('tr-offline-dns-query');
  const question=query.subarray(12,offset+5);
  const answer=Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,198,51,100,7]);
  const reply=Buffer.alloc(12+question.length+answer.length);
  query.copy(reply,0,0,2);reply.writeUInt16BE(0x8180,2);
  reply.writeUInt16BE(1,4);reply.writeUInt16BE(1,6);
  question.copy(reply,12);answer.copy(reply,12+question.length);
  server.send(reply,remote.port,remote.address);
});server.bind(${canaryPort},'0.0.0.0');`;

export const apiEgressDnsScript = `const resolver=new (require('node:dns')).Resolver({timeout:1500,tries:1});resolver.setServers([process.argv[1]+':'+process.argv[2]]);resolver.resolve4('${dnsCanaryName}',(error,addresses)=>{if(error){console.log('denied:'+error.code);process.exitCode=7}else{console.log('resolved:'+addresses[0])}})`;
