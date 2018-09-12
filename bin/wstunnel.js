const globalTunnel = require('global-tunnel-ng');
const urlParse = require('url').parse;
const crypto = require('crypto');

var chroot
try{
    chroot =  require('chroot');
}catch(e){
    chroot = null;
}

const Help = `
Run websocket tunnel server or client.
 To run server: wstunnel -s 0.0.0.0:8080
 To run client: wstunnel -t localport:host:port ws[s]://wshost:wsport
 Or client via proxy: wstunnel -t localport:host:port -p http://[user:pass@]host:port ws[s]://wshost:wsport

Now connecting to localhost:localport is same as connecting to host:port on wshost

For security, you can "lock" the tunnel destination on server side, for eample:
 wstunnel -s 0.0.0.0:8080 -t host:port
Server will tunnel incomming websocket connection to host:port only, so client can just run
 wstunnel -t localport ws://wshost:port
If client run:
 wstunnel -t localport:otherhost:otherport ws://wshost:port
 * otherhost:otherport is ignored, tunnel destination is still "host:port" as specified on server.

In client mode, you can bind stdio to the tunnel by running:
 wstunnel -t stdio:host:port ws[s]://wshost:wsport
This allows the command to be used as ssh proxy:
 ssh -o ProxyCommand="wstunnel -c -t stdio:%h:%p https://wstserver" user@sshdestination
Above command will ssh to "user@sshdestination" via the wstunnel server at "https://wstserver"
`;

module.exports = (Server, Client) => {
    const optimist = require('optimist')
    let argv = optimist
        .usage(Help)
        .string("s")
        .string("t")
        .string("p")
        .string("H")
        .string("k")
        .string("chroot")
        .string("chuser")
        .string("idheader")
        .alias('k', "authkey")
        .alias('p', "proxy")
        .alias('t', "tunnel")
        .boolean('c')
        .boolean('http')
        .alias('c', 'anycert')
        .default('c', false)
        .describe('s', 'run as server, listen on [localip:]localport, default localip is 127.0.0.1')
        .describe('tunnel', 'run as tunnel client, specify [localip:]localport:host:port')
        .describe("proxy", "connect via a http proxy server in client mode")
        .describe("chroot", "chroot path")
        .describe("chuser", "drop privileges to this user")
        .describe("authkey", "Authentication key")
        .describe("c", "accept any certificates")
        .describe("H", "additional headers")
        .argv;

    const uuid_header = argv.idheader ? argv.idheader.toString() : 'x-wstclient';

    if (argv.s) {
        let server;
        if (argv.t) {
            let [host, port] = argv.t.split(":")
            server = new Server(argv.authkey, uuid_header, host, port)
        } else {
            server = new Server(argv.authkey, uuid_header)
        }
        server.start(argv.s, (err) => {
            if (err) return;
            console.log(` Server is listening on ${argv.s}`);
            if (chroot !== null && process.getuid() === 0 && argv.chroot && argv.chuser) {
                chroot(argv.chroot.toString(), argv.chuser.toString());
                console.log(`Changed root to "${argv.chroot}" and user to "${argv.chuser}"`);
            }
        })
    } else if (argv.t) {
        // client mode
        function tryParse(url) {
            if (!url) {
                return null;
            }
            var parsed = urlParse(url);
            return {
                protocol: parsed.protocol,
                host: parsed.hostname,
                port: parseInt(parsed.port, 10),
                proxyAuth: parsed.auth
            };
        }

        crypto.randomBytes(20, (err, buf) => {
            if (err) throw err;

            let machineId = buf.toString('hex');

            let conf = {};
            if (argv.proxy) {
                conf = tryParse(argv.proxy);
                if (argv.c) {
                    conf.proxyHttpsOptions = {rejectUnauthorized: false};
                    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
                }
                globalTunnel.initialize(conf);
            } else {
                require("../lib/httpSetup").config(argv.proxy, argv.c)
            }

            let headers = {};
            if (argv.H) {
                if (Array.isArray(argv.H)) {
                    for (let i = 0; i < argv.H.length; ++i) {
                        let parts = argv.H[i].split(':');
                        if (parts.length < 2) continue;
                        headers[parts[0].trim()] = parts[1].trim();
                    }
                } else {
                    let parts = argv.H.split(':');
                    if (parts.length >= 2)
                        headers[parts[0].trim()] = parts[1].trim();
                }
            }
            headers[uuid_header] = machineId;

            let client = new Client(argv.authkey, uuid_header)
            if (argv.http) {
                client.setHttpOnly(true)
            }

            let wsHostUrl = argv._[0]
            client.verbose()

            let DefaultLocalIp = "127.0.0.1"
            let localAddr
            let remoteAddr
            let toks = argv.t.split(":")
            if (toks.length === 4) {
                localAddr = `${toks[0]}:${toks[1]}`
                remoteAddr = `${toks[2]}:${toks[3]}`
            } else if (toks.length === 3) {
                remoteAddr = `${toks[1]}:${toks[2]}`
                if (toks[0] === 'stdio') {
                    client.startStdio(wsHostUrl, remoteAddr, headers, (err) => {
                        if (err) {
                            console.error(err.message)
                            process.exit(1)
                        } else if (chroot !== null && process.getuid() === 0 && argv.chroot && argv.chuser) {
                            chroot(argv.chroot.toString(), argv.chuser.toString());
                        }
                    })
                    return;
                } else {
                    localAddr = `${DefaultLocalIp}:${toks[0]}`
                }
            } else if (toks.length === 1) {
                localAddr = `${DefaultLocalIp}:${toks[0]}`
            }
            client.start(localAddr, wsHostUrl, remoteAddr, headers, (err) => {
                if (err) {
                    console.error("Can't establish WSTunnel, abort")
                    process.exit(1)
                } else {
                    let url = urlParse(wsHostUrl)
                    if (argv.proxy) {
                        let prxy = urlParse(argv.proxy);
                        console.log(`Client tunneling tcp://${localAddr} -> ${prxy.protocol}//${prxy.host}${url.port ? ':' + url.port : ''} -> ${url.protocol}//${url.host}${url.port ? ':' + url.port : ''} -> tcp://${remoteAddr}`);
                    } else {
                        console.log(`Client tunneling tcp://${localAddr} -> ${url.protocol}//${url.host}${url.port ? ':' + url.port : ''} -> tcp://${remoteAddr}`);
                    }

                    if (chroot !== null && process.getuid() === 0 && argv.chroot && argv.chuser) {
                        chroot(argv.chroot.toString(), argv.chuser.toString());
                        console.log(`Changed root to "${argv.chroot}" and user to "${argv.chuser}"`);
                    }
                }
            });
        });
    } else {
        return console.log(optimist.help());
    }
};

