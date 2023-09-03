const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const crypto = require('crypto');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { e64, d64, prepareKey, prepareKeyV2, formatKey, AES, constantTimeCompare } = require('./crypto/index.js');
const { cryptoDecodePrivKey, cryptoRsaDecrypt } = require('./crypto/rsa.js');


module.exports = class Checker {
    constructor(data) {
        this.email = data.email;
        this.password = data.password;
        this.authData = null;
        this.proxy = data.proxy || null
		this.counterId = Math.random().toString().substr(2, 10);
		this.sid = null;
		this.VersionLogin = null;
    }


 async decrypt(b, aes) {
		
		if(b.tsid) return b.tsid;
		this.key = formatKey(b.k)
        aes.decryptECB(this.key)
        this.aes = new AES(this.key)

        const t = formatKey(b.csid)
		
        const privk = this.aes.decryptECB(formatKey(b.privk))
        const rsaPrivk = cryptoDecodePrivKey(privk)
        if (!rsaPrivk) return [-16];

        const sid = e64(cryptoRsaDecrypt(t, rsaPrivk).slice(0, 43))
		this.sid = sid;
		this.authData = rsaPrivk;

 }

	async getUser() {

		const response = await this.req( { a: 'ug' }, { id: (this.counterId++).toString(), sid: this.sid });
		return response;
		
	}
	async bytesToGigabytes(bytes) {
	  const gigabytes = bytes / (1024 * 1024 * 1024);
	  return gigabytes.toFixed(2); 
	}
	async getAccountInfo() {

		const response = (await this.req( { a: 'uq', strg: 1, xfer: 1, pro: 1 }, { id: (this.counterId++).toString(), sid: this.sid }))[0];
		
	  const account = {};
	  account.type = response.utype;
      account.spaceUsed = await this.bytesToGigabytes(response.cstrg);
      account.spaceTotal = await this.bytesToGigabytes(response.mstrg);
      account.downloadBandwidthTotal = await this.bytesToGigabytes(response.mxfer || Math.pow(1024, 5) * 10);
      account.downloadBandwidthUsed = await this.bytesToGigabytes(response.caxfer || 0);
      account.sharedBandwidthUsed = await this.bytesToGigabytes(response.csxfer || 0);
      account.sharedBandwidthLimit = await this.bytesToGigabytes(response.srvratio);
		
		return account;
		
	}

	async loginV1(s, qs) {
		  const pw = prepareKey(Buffer.from(this.password));

		  const aes = new AES(pw);
		  const uh = e64(aes.stringhash(Buffer.from(this.email)));
            const response = await this.req({ a: 'us', user: this.email, uh }, qs);
			if(typeof response[0] == 'number') return false;
			await this.decrypt(response[0], aes);
			const user = await this.getUser();
			if(typeof user == 'number') return false;
			user.push({version: this.VersionLogin});
			user.push(await this.getAccountInfo());
			if(typeof user == 'object') return user;
        }


	async loginV2(s, qs) {
      const pw = await prepareKeyV2(Buffer.from(this.password), s);
        const aes = new AES(pw.slice(0, 16));
        const uh = e64(pw.slice(16));
            const response = await this.req({ a: 'us', user: this.email, uh }, qs);
			if(typeof response[0] == 'number') return false;
			await this.decrypt(response[0], aes);
			const user = await this.getUser();
			if(typeof user == 'number') return false;
			user.push({version: this.VersionLogin});
			user.push(await this.getAccountInfo());
			if(typeof user == 'object') return user;
        }
		

    async Auth() {
			const qs = { id: (this.counterId++).toString() };
		    const l1 = await this.req({ a: 'us0', user: this.email }, qs);
			this.VersionLogin = l1[0].v;
			if(l1[0].v === 2) return await this.loginV2(l1[0], qs);
			if(l1[0].v === 1) return await this.loginV1(l1[0], qs);
        }
		
	async req(data, qs) {
		 const res = await (await fetch("https://g.api.mega.co.nz/cs?" + new URLSearchParams(qs), {
				  method: 'POST',
				  headers: { 'Content-Type': 'application/json' },
				  agent: this.proxy ? new SocksProxyAgent(this.proxy) : null,
				  body: JSON.stringify([data])
				})).json();
				
			return res;
	}
}