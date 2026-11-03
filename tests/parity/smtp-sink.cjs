// Minimal SMTP sink for tests: accepts every message on port 2525 (or SMTP_SINK_PORT) and keeps nothing.
const net = require('net');
net.createServer(s => {
  let data = false, buf = '';
  s.write('220 sink\r\n');
  s.on('data', d => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf('\r\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (data) { if (line === '.') { data = false; s.write('250 OK\r\n'); } continue; }
      const c = line.slice(0, 4).toUpperCase();
      if (c === 'EHLO') s.write('250-sink\r\n250 OK\r\n');
      else if (c === 'DATA') { data = true; s.write('354 go\r\n'); }
      else if (c === 'QUIT') { s.end('221 bye\r\n'); }
      else s.write('250 OK\r\n');
    }
  });
  s.on('error', () => {});
}).listen(Number(process.env.SMTP_SINK_PORT || 2525), () => console.log("smtp sink listening"));
