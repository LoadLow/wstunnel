let wst_server;
const WebSocketServer = require('websocket').server;
const http = require('http');
const url = require("url");
const net = require("net");
const WsStream = require("./WsStream");
const log = require("lawg");
const HttpTunnelServer = require("./httptunnel/Server");
const HttpTunnelReq = require("./httptunnel/ConnRequest");
const ChainedWebApps = require("./ChainedWebApps");
const resolveIP = require("./httpReqRemoteIp");
const bindStream = require("./bindStream");
const crypto = require("crypto");

module.exports = (wst_server = class wst_server {

  // if dstHost, dstPort are specified here, then all tunnel end points are at dstHost:dstPort, regardless what
  // client requests, for security option
  // webapp: customize webapp if any, you may use express app
  constructor(sharedSecret, uid_header, dstHost, dstPort, webapp) {
    this.dstHost = dstHost;
    this.dstPort = dstPort;
    this.sharedSecret = sharedSecret;
    this.uid_header = uid_header;
    this.httpServer = http.createServer();
    this.wsServer = new WebSocketServer({
      httpServer: this.httpServer,
      autoAcceptConnections: false
    });
    // each app is http request handler function (req, res, next),  calls next() to ask next app
    // to handle request
    const apps = new ChainedWebApps();
    this.tunnServer = new HttpTunnelServer(apps);
    if (webapp) {
      apps.setDefaultApp(webapp);
    }
    apps.bindToHttpServer(this.httpServer);
  }

  // localAddr:  [addr:]port, the local address to listen at, i.e. localhost:8888, 8888, 0.0.0.0:8888
  start(localAddr, cb) {
    const [localHost, localPort] = Array.from(this._parseAddr(localAddr));
    return this.httpServer.listen(localPort, localHost, err => {
      if (cb) { cb(err); }

      const handleReq = (request, connWrapperCb) => {
        const { httpRequest } = request;
        return this.authenticate(httpRequest, (rejectReason, target, monitor) => {
          if (rejectReason) {
            return request.reject(500, JSON.stringify(rejectReason));
          }
          const {host, port} = target;
          var tcpConn = net.connect({host, port, allowHalfOpen: false}, () => {
            tcpConn.removeAllListeners('error');
            const ip = resolveIP(httpRequest);
            log(`Client ${ip} establishing ${request instanceof HttpTunnelReq ? 'http' : 'ws'} tunnel to ${host}:${port}`);
            let wsConn = request.accept('tunnel-protocol', request.origin);
            if (connWrapperCb) { wsConn = connWrapperCb(wsConn); }
            bindStream(wsConn, tcpConn);
            if (monitor) { return monitor.bind(wsConn, tcpConn); }
          });

          return tcpConn.on("error", err => request.reject(500, JSON.stringify(`Tunnel connect error to ${host}:${port}: ` + err)));
        });
      };

      this.wsServer.on('request', req => {
        return handleReq(req, wsConn =>
          // @_patch(wsConn)
          new WsStream(wsConn)
        );
      });
      return this.tunnServer.on('request', req => {
        return handleReq(req);
      });
    });
  }

  // authCb(rejectReason, {host, port}, monitor)
  authenticate(httpRequest, authCb) {
    let host, port;
    if (this.dstHost && this.dstPort) {
      [host, port] = Array.from([this.dstHost, this.dstPort]);
    } else {
      const dst = this.parseUrlDst(httpRequest.url, httpRequest.headers);
      if (!dst) {
        return authCb('Unable to determine tunnel target');
      } else { ({host, port} = dst); }
    }
    return authCb(null, {host, port});  // allow by default
  }

  // returns {host, port} or undefined
  parseUrlDst(requrl, reqheaders) {
    try {
      const uri = url.parse(requrl, true);
      if (!uri.query.tkn) {
          return undefined;
      } else {
          let tkn = Buffer.from(decodeURIComponent(uri.query.tkn), 'base64').toString('ascii')
          if(!this.sharedSecret) {
              const [host, port] = Array.from(tkn.split(":"));
              return {host, port};
          } else {
              let parts = tkn.split(":");
              const [host, port] = [parts[0], parts[1]];
              let csig = crypto.createHmac("sha256", this.sharedSecret)
                  .update(reqheaders[this.uid_header] + ':' + parts[0]+':'+parts[1]).digest();
              return crypto.timingSafeEqual(csig, Buffer.from(parts[2], 'hex')) ? {host, port} : undefined;
          }
      }
    }catch(e) {
      return undefined;
    }
  }

  _parseAddr(localAddr) {
    let localHost, localPort;
    if (typeof localAddr === 'number') {
      localPort = localAddr;
    } else {
      [localHost, localPort] = Array.from(localAddr.split(':'));
      if (/^\d+$/.test(localHost)) {
        localPort = localHost;
        localHost = null;
      }
      localPort = parseInt(localPort);
    }
    if (localHost == null) { localHost = '127.0.0.1'; }
    return [localHost, localPort];
  }

  _patch(ws) {
    return ws.drop = function(reasonCode, description, skipCloseFrame) {
      this.closeReasonCode = reasonCode;
      this.closeDescription = description;
      this.outgoingFrameQueue = [];
      this.frameQueue = [];
      this.fragmentationSize = 0;
      if (!skipCloseFrame) {
        this.sendCloseFrame(reasonCode, description, true);
      }
      this.connected = false;
      this.state = "closed";
      this.closeEventEmitted = true;
      this.emit('close', reasonCode, description);
      // ensure peer receives the close frame
      return this.socket.end();
    };
  }
});

