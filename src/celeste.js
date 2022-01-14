//---   Imports   ---//
const fs = require('fs');
const uuid_tool = require('uuid');
const express = require('express');
const http = require('http');
const https = require('https');
const bodyParser = require('body-parser');
const path = require('path');
const formidable = require('formidable');
const compression = require('compression')
const db = require("quick.db")
const crypto = require("crypto")
const cookieParser = require("cookie-parser");
const nodemailer = require('nodemailer');
const { json } = require('body-parser');

//---   Variables   ---//
const maindomain = "";
const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const id_length = 8;
const bot_api_key = "";
const whitelist_gen_key = "";
const psw_salt = "";
const file_extensions = ["png", "jpg", "jpeg", "gif", "mp4", "webp", "webm"];
const defaults = {
    embedtitle: '{filename} ({size})',
    embeddescription: 'Uploaded by {username} on {date} at {time}',
    embedcolor: '#8F5CFF',
    domain: ''
};

//---   Compile Express   ---//
var app = express();
var dir = path.join(__dirname, 'public');
app.use(compression());
app.use(express.static(dir));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

//---   Make ALL Files Public  ---//
app.use('/', express.static('public'), compression());

//---   Splash Screen   ---
console.log("╔═════════════════════════════════╗")
console.log("║Front's Core.JS            V2.1.0║")
console.log("╠═════════════════════════════════╝")
console.log("╚  Starting @: ", __dirname);

//---   Email Settings   ---//
let transporter = nodemailer.createTransport({
    host: '',
    secure: true,
    port: 465,
    auth: {
        user: '',
        pass: '',
    },
});


//---   SSL/HTTPS   ---//
const options = {
    key: fs.readFileSync('ssl/privkey.pem'),
    cert: fs.readFileSync('ssl/cert.pem')
};

const server = app.listen(80);
https.createServer(options, app).listen(443);

//---   Redirect Pages Correctly   ---//
app.get('/', (req, res) => {
    res.sendFile('./public/index.html', { root: __dirname });
});

app.get('/login', (req, res) => {
    if(req.get('host') !== 'celestephoto.com') return res.redirect('https://celestephoto.com/login');
    if(req.cookies.token && db.get('account').some(u => u.token === req.cookies.token)) return res.redirect('/dashboard');
    res.sendFile('./public/login.html', { root: __dirname });
});

app.get('/staff_login', (req, res) => {
    if(req.get('host') !== 'celestephoto.com') return res.redirect('https://celestephoto.com/staff_login');
    if(req.cookies.token && db.get('account').some(u => u.token === req.cookies.token)) return res.redirect('/staff');
    res.sendFile('./public/staff_login.html', { root: __dirname });
});


app.get('/register', (req, res) => {
    if(req.get('host') !== 'celestephoto.com') return res.redirect('https://celestephoto.com/register');
    if(req.cookies.token && db.get('account').some(u => u.token === req.cookies.token)) return res.redirect('/dashboard');
    res.sendFile('./public/register.html', { root: __dirname });
});

app.get('/staff', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.cookies.token);
    if(!account){
        res.clearCookie('token');
        res.redirect('/staff_login');
        return;
    };
    if(!account.premium || account.premium === 'Basic'){
        return res.send(`<html>
            <head>
                <title>Celeste - Access Denied</title>
                <link rel="stylesheet" href="/assets/css/error.css" />
            </head>
            <body>
                <center>
                    <div class="box">
                        <h3>Access Denied</h3>
                        <h4>You do not have permission to access this.</h4><br><br>
                        <h4>Account type: 
                        <span class="info">${account.premium}</span>
                        </h4>
                    </div>
                </center>
            </body>
        </html>`)
    }else{
        res.sendFile('./public/staff_alpha.html', { root: __dirname });
    };
});

app.get('/dashboard', (req, res) => {
    if(req.get('host') !== 'celestephoto.com') return res.redirect('https://celestephoto.com/dashboard');
    const account = db.get("account").find(({ token }) => token === req.cookies.token);
    if (account) {
        if (account.mailverified) {
            res.sendFile('./public/dashboard.html', { root: __dirname });
        } else {
            res.redirect("/verify");
        }
    } else {
        res.clearCookie('token');
        res.redirect("/login") //Token Is Blank
    }
});

app.get('/discord', (req, res) => {
    res.status(301).redirect('https://discord.gg/c6WPqQ2uKa');
});

app.get('/verify', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.cookies.token);
    if (account) {
        if(account.mailverified) return res.redirect('/dashboard');
        res.send(`<title>Account Verification</title>
		<link href="assets/css/verify.css" rel="stylesheet"/>
		<center>
		<p>Please verify your email.<br>${account.email}</p><br><br>
		<button id="send" onclick='send();'>Resend Verification</button>
		<p id="sent" class="sent">Verification Sent</p>
		</center>
		<script>
		function send() {
			document.getElementById('send').style.display = "none";
			document.getElementById('sent').style.display = "inline";

			var http = new XMLHttpRequest();
			http.open("POST", "/verify", true);
			http.send();
		}
		</script>`);
    } else {
        res.send("Error getting account details");
    }
});

app.post('/verify', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.cookies.token);
    if (account) {
        const mailOptions = {
            from: 'noreply@celestephoto.com',
            to: account.email,
            subject: 'Account Verification',
            html: `<p>To verify your Celeste account, please click the link below.<br>https://celestephoto.com/v?id=${account.token}</p>`,
        };
        transporter.sendMail(mailOptions, function(err, info) { if (err) { throw err; } });
        console.log(`Verification Mail Resent For ${account.email}`)
    } else {
        res.redirect("/");
    }
});

app.get('/v', (req, res) => {
    var account = db.get("account").find(({ token }) => token === req.query.id);
    if (account) {
        const giventoken = account.token;

        var accounts = db.get('account');
        account = db.get("account").find(u => u.token === giventoken);

        account.mailverified = true;

        accounts = accounts.filter(function(acc) {
            return acc.token !== account.token;
        });
        accounts.push(account);
        db.set('account', accounts);

        res.redirect("/dashboard")
        res.end();
    } else {
        res.redirect("/");
    }
});

// Domains
app.get('/domains', (req, res) => {
    const domains = JSON.parse(fs.readFileSync('public/domains.json'));
    
    var $domains = "";
    for(const name in domains){
        let tags = '';
        if(domains[name].tags){
            for(const tag in domains[name].tags){
                const color = domains[name].tags[tag];
                tags+=`<button${color ? ` style="background-color:${color}"` : ''}>${tag}</button>\n`;
            };
        };
        $domains+=`<tr>
        <td>${name}</td>
       <td>${tags.length > 0 ? tags : 'None'}</td>
        </tr>\n`;
    };

    res.send(`<!DOCTYPE html>
    <head>
        <title>Celeste - Domains</title>
        <meta property="og:title" content="Celeste - Domains" />
        <meta property="og:description" content="The domains Celeste currently has" />
        <meta property="og:image" content="/assets/favicon.png" />
        <meta name="theme-color" content="${defaults.embedcolor}" />
        <link rel="stylesheet" href="/assets/css/domains.css">
        <script src="/assets/js/CustomRightClick.js"></script>
    </head>
    <body>
        <center>
            <div style="overflow-x:auto;">
                <table>
                    <tr>
                        <th>Domain</th>
                        <th>Tags</th>
                    </tr>
                    ${$domains}
                </table>
            </div>
        </center>
    </body>`);
});

//Email Reset
app.get('/api/reset/email', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.query.token);
    const email = req.query.email
    if (account) {
        if (email) {
            var accounts = db.get('account');
            account.email = email;
            accounts = accounts.filter(function(acc) {
                return acc.token !== account.token;
            });
            accounts.push(account);
            db.set('account', accounts);

            res.send(`Complete`);
        } else {
            res.send(`Please provide an email`);
        }
    } else {
        res.send(`Please provide a token and email`);
    }
});

//--- User Pages ---//

app.get('/user/:uuid', (req, res, next) => {
    const { uuid } = req.params;
    const user = db.get('account').find(u => u.uuid === uuid || u.name === uuid);
    if(!user) return next();
    const username = user.name;
    if (!fs.existsSync(`public/cdn/${user.uuid}`)) fs.mkdirSync(`public/cdn/${user.uuid}`);
    const pfpExists = fs.existsSync(`public/cdn/${user.uuid}/profile.png`);
    const files = fs.readdirSync(`public/cdn/${user.uuid}`).length;
    res.writeHeader(200, { "Content-Type": "text/html" });
    res.write(`

    <html prefix="og: https://ogp.me/ns#">
       <head>
          <title>${username}</title>
          <meta property="og:title" content="${username} on Celeste" />
          <meta property="og:description" content="${username} has uploaded a total of ${files} files." />
          <meta property="og:image" content="${pfpExists ? `https://celestephoto.com/cdn/${user.uuid}/profile.png?${Date.now()}` : 'https://celestephoto.com/assets/favicon.png'}" />
          <meta name="theme-color" content="${user.embedcolor || defaults.embedcolor}" />
          <link rel="shortcut icon" href="${pfpExists ? `/cdn/${user.uuid}/profile.png?${Date.now()}` : '/assets/favicon.png'}" />
          <link rel="stylesheet" href="/assets/css/user.css" />
          <script src="/assets/js/CustomRightClick.js"></script>
       </head>
       <body>
          <center>
             <div class="box">
             ${pfpExists ? `<img src="/cdn/${user.uuid}/profile.png?${Date.now()}">` : ''}
                <h3>
                   Username: <span class="info">${username}</span>
                </h3><br>
                <h4>
                    Account Type: <span class="info">${user.premium}</span>
                </h4><br>
                <h4>
                    UUID: <span class="info">${user.uuid}</span>
                </h4>
                <br>
                <h4>
                    Files Uploaded: <span class="info">${files}</span>
                </h4>
             </div>
          </center>
       </body>
    </html>`);
    res.end();
});

//--- Redirect For Embeds V2 ---//
app.get('/:imageid', (req, res, next) => {

    if(req.get('host') === 'celestephoto.com') return next();
    // Set Variables //
    const { imageid } = req.params;
    const image = db.get('images').find(i => i.id === imageid);
    if(!image) return next();
    const user = db.get('account').find(u => (u.email && u.email === image.email) || (u.uuid === image.uuid));
    if(!user) return res.send('An error occurred locating the file owner.');
    if(!fs.existsSync(`public/cdn/${user.uuid}/${imageid}`)){
        const images = db.get('images').filter(function(i) {
            return i.id !== imageid;
        });
        db.set('images', images);
        return res.send('Unknown file');
    };
    var { embedtitle, embeddescription, embedcolor, name } = user;
    embedtitle = toHTML(embedtitle || defaults.embedtitle);
    embeddescription = toHTML(embeddescription || defaults.embeddescription);
    embedcolor = embedcolor || defaults.embedcolor;
    const embedimage = `https://celestephoto.com/cdn/${user.uuid}/${imageid}`;
    const isVideo = imageid.endsWith('.mp4') || imageid.endsWith('.webm');

    // Set Custom Variables //
    const imageStats = fs.statSync(`public/cdn/${user.uuid}/${imageid}`);

    const birth = new Date(imageStats.birthtimeMs);

    const date = `${("0" + (birth.getMonth() + 1)).slice(-2)}/${("0" + birth.getDate()).slice(-2)}/${birth.getFullYear()}`;
    const time = `${((birth.getHours() < 10 ? '0' : '') + birth.getHours())}:${((birth.getMinutes() < 10 ? '0' : '') + birth.getMinutes())}`;

    const filesize = (imageStats.size / Math.pow(1024, (Math.floor(Math.log(imageStats.size) / Math.log(1024))))).toFixed(2) * 1 + ['B', 'KB', 'MB', 'GB', 'TB'][Math.floor(Math.log(imageStats.size) / Math.log(1024))];

    // Set What To Replace //
    const $replace = {
        "date": date,
        "time": time,
        "size": filesize,
        "username": name,
        "filename": imageid,
        "domain": req.get('host') || (user.domain || defaults.domain),
    };

    for(var key in $replace){
        const value = $replace[key];
        key = `{${key}}`;
        embedtitle = embedtitle.split(key).join(value);
        embeddescription = embeddescription.split(key).join(value);
    };

    

    // Write html header //
    res.writeHeader(200, { "Content-Type": "text/html" });

    // Respond //
    res.write(`<html prefix="og: https://ogp.me/ns#">
    <head>
       <title>${name} on Celeste</title>
       <meta charset="UTF-8">
       ${isVideo ? `<meta name="twitter:card" content="player" />
       <meta name="twitter:player" content="${embedimage}" />` : `<meta property="og:image" content="${embedimage}" />
       <meta name="twitter:card" content="summary_large_image" />`}
       ${user.showembed ? `${user.showauthor ? `
       <link type="application/json+oembed" href="https://celestephoto.com/api/author/${name}" />
       ` : ''}
       <meta property="og:title" content="${embedtitle}" />
       <meta property="og:description" content="${embeddescription}" />
       <meta name="theme-color" content="${embedcolor}" />` : ''}
       <link rel="shortcut icon" href="/assets/favicon.png" />
       <link rel="stylesheet" href="/assets/css/cdn.css" />
       <script src="/assets/js/CustomRightClick.js"></script>
    </head>
    <body>
       <center>
          <div class="box">
             <h3>
                ${imageid}
                (<span class="info">${filesize}</span>)
             </h3>
             <a href="${embedimage}" target="_blank">
                ${isVideo ? `<video src="${embedimage}" autoplay loop controls>Your browser does not support video playback.</video>` : `<img src="${embedimage}">`}
             </a>
             <h4>
                Uploaded by: 
                <span class="info">
                    <a href="https://celestephoto.com/user/${user.uuid}">${name}</a>
                </span>
             </h4>
             <h4>
                Uploaded at: 
                <span class="info">${date}</span> at 
                <span class="info">${time}</span> (<span class="info">UTC</span>)
             </h4>
          </div>
       </center>
    </body>
 </html>`);
res.end();
});

//---   Setup Embeds V1.0   ---//
app.get('/api/author/:name', (req, res) => {
    res.send(JSON.stringify({
        type: 'photo',
        author_name: req.params.name
    }));
});

app.post('/api/embed', (req, res) => {
    const hexRegex = /^#[0-9A-F]{6}$/i;
    var showembed = req.body.enabled || false;
    var title = req.body.title;
    var description = req.body.description;
    var color = req.body.hexcolor;
    var showauthor = req.body.showauthor || false;
    const giventoken = req.cookies.token;
    var accounts = db.get('account');
    const account = db.get("account").find(u => u.token === giventoken);

    if (!account) { res.send("No Account Found"); return; }
    if(!account.mailverified) return res.status(403).send('Your account is not verified.');
    
    if(!showembed && account.showauthor && !showauthor) showauthor = account.showauthor.toString();

    if(title && title.length > 70) return res.send('Embed title cannot exceed 70 characters.');
    if(description && description.length > 350) return res.send('Embed description cannot exceed 350 characters.');
    account.embedtitle = title || account.embedtitle || '';
    account.embeddescription = description || account.embeddescription || '';
    account.embedcolor = (color || account.embedcolor || defaults.embedcolor).toLowerCase();
    account.showauthor = (showauthor == 'true' ? true : false);
    account.showembed = (showembed == 'true' ? true : false);

    if(account.embedtitle.length < 1) delete account.embedtitle;
    if(account.embeddescription.length < 1) delete account.embeddescription;
    if(!hexRegex.test(account.embedcolor) || account.embedcolor === defaults.embedcolor) delete account.embedcolor;

    accounts = accounts.filter(function(acc) {
        return acc.token !== account.token;
    });
    accounts.push(account);
    db.set('account', accounts);

    res.send('success');


});

//---   Setup Domains V1.0   ---//
function validateDomain(domain){
    const domains = JSON.parse(fs.readFileSync('public/domains.json'));
    if(domains[domain]) return true;
    domain = domain.split('.').slice(1).join('.');
    if(domains[domain]) return true;
    return false;
};


app.post('/api/domain', (req, res) => {
    const regex = /^[A-Za-z0-9-]*$/;
    const { domain, subdomain } = req.body;
    if(subdomain.length > 100) return res.send('Subdomain length cannot be greater than 100 characters!');
    const givendomain = (subdomain.length > 0 ? `${subdomain}.${domain}` : domain).toLowerCase();
    const giventoken = req.cookies.token;

    var accounts = db.get('account');
    const account = db.get("account").find(u => u.token === giventoken);

    if (!account) { res.send("No Account Found"); return; }
    if(!account.mailverified) return res.status(403).send('Your account is not verified.');

    if(subdomain.startsWith('-') || subdomain.endsWith('-')) return res.send('Subdomain cannot start or end with -');
    if(!regex.test(subdomain)) return res.send('Invalid subdomain');
    if(!validateDomain(givendomain)) return res.send('Invalid domain.');
    account.domain = givendomain;
    if(account.domain === defaults.domain) delete account.domain;

    accounts = accounts.filter(function(acc) {
        return acc.token !== account.token;
    });
    accounts.push(account);
    db.set('account', accounts);

    res.send('success');


});

//---   Login Auth V2.1 Beta   ---//

app.all('/logout', (req, res, next) => {
    if(!db.get('account').some(u => u.token === req.cookies.token)) return next();
    res.clearCookie('token');
    res.redirect('/');
});

app.post('/api/login', (req, res) => {
    var username = req.body.uname;
    var password = req.body.psw;
    var { type } = req.query;


    const account = db.get("account").find(u => u && u.name && u.name === req.body.uname);
    if (!account) return res.send('Invalid credentials');

    if (username == account.name) {
        var hashedpassword = crypto.createHash('md5').update(`${psw_salt}${password}`).digest("hex");
        if (hashedpassword == account.password) {
            //Valid Credentials
            
            if (account.mailverified) {
                res.cookie('token', account.token, { maxAge: 315569260000 });
                    res.send('success')
            } else {
                res.cookie('token', account.token, { maxAge: 315569260000 })
                res.redirect('success');
                res.end();
            }
        } else {
            //Invalid Credentials
            res.send('Invalid credentials');
        }
    } else {
        //Invalid Credentials
        res.send('Invalid credentials');
    }


});

//--- Get Uploads From Token ---//
app.post('/api/uploads', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    const files = fs.readdirSync(`public/cdn/${account.uuid}/`).filter(f => f !== 'profile.png');

    const uploads = [];

    for(const name of files){
        uploads.push(`/cdn/${account.uuid}/${name}`);
    };

    res.send(uploads);
});

//--- Get Domain From Token ---//
app.post('/api/getdomain', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    console.log(`Returning: ${account.domain || defaults.domain} for token: ${account.token}`);
    res.send(account.domain || defaults.domain);
});

//--- Get UUID From Token ---///
app.post('/api/uuid', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    console.log(`Returning: ${account.uuid} for token: ${account.token}`);
    res.send(account.uuid);
});

//---   Get Username From Token V2.1   ---//
app.post('/api/token', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    console.log(`Returning: ${account.name} for token: ${account.token}`);
    res.send(account.name);
});

//---   Get Account Type From Token V2.1   ---//
app.post('/api/premium', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    console.log(`Returning: ${account.premium} for token: ${account.token}`);
    res.send(account.premium);
});

//---   Get User Photos V2.1   ---//
app.post('/api/photos', (req, res) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);

    if (!account) { res.send("No Account Found"); return; }

    if (!fs.existsSync('public/cdn/' + account.uuid + '/')) {
        fs.mkdirSync('public/cdn/' + account.uuid + '/');
    }
        const photos = fs.readdirSync(`public/cdn/${account.uuid}`).filter(f => f !== 'profile.png').length.toString();
        res.send(photos);



});

//---   Get Settings V1.0   ---//
app.post('/api/settings', (req, res, next) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);
    if (!account) { res.send("No Account Found"); return; }    const info = `${account.domain || defaults.domain}██${account.embedtitle || ''}██${account.embeddescription || ''}██${account.embedcolor || defaults.embedcolor}██${(account.showauthor ? account.showauthor.toString() : 'false')}██${(account.showembed ? account.showembed.toString() : 'false')}`
    res.send(info)

});

//---   Purge User Data V2.1 Beta   ---//
app.post('/api/purge', (req, res, next) => {
    const account = db.get("account").find(({ token }) => token === req.body.token);
    if (!account) { res.send("No Account Found"); return; }
    
    if (fs.existsSync('public/cdn/' + account.uuid + '/') && fs.readdirSync(`public/cdn/${account.uuid}`).length > 0) {
        fs.rmdir('public/cdn/' + account.uuid + '/', { recursive: true }, (err) => {
            if (err) {
                res.send(err);
                throw err;
            } else {
                console.log("Account Purged: " + account.name);
                res.send('purged');
            }
        })
    }else{
        res.send('You have no uploads.')
    }
});

//---   Register User Account ---//
function isAlphaNumeric(str) {
    var code, i, len;
    for (i = 0, len = str.length; i < len; i++) {
        code = str.charCodeAt(i);
        if (!(code > 47 && code < 58) && // numeric (0-9)
            !(code > 64 && code < 91) && // upper alpha (A-Z)
            !(code > 96 && code < 123)) { // lower alpha (a-z)
            return false;
        }
    }
    return true;
};

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
};




function arrayRemove(arr, value) {
    return arr.filter(function(ele) {
        return ele != value;
    });
}

function generateUUID(){
    const accounts = db.get('account');
    var uuid = uuid_tool.v4();
    if(accounts.some(u => u.uuid === uuid)) return generateUUID();
    return uuid;
};

app.post('/api/register', (req, res) => {
    var form = req.body;

    if (!db.get("whitelists").includes(form.key)) {
        res.send('Invalid invite key.');
        return;
    }


    if (isAlphaNumeric(form.uname)) {

        if(form.uname.length > 15 || form.uname.length < 3) return res.send('Username must be between 3 and 15 characters long.');

        if (db.has("account")) {
            const checkname = db.get("account").some(({ name }) => name && name.toLowerCase() === form.uname.toLowerCase());
            const checkemail = db.get("account").some(({ email }) => email && email.toLowerCase() === form.email.toLowerCase());

            if (checkname) {
                res.send('Username already exists.');
                return;
            }
            if (checkemail) {
                res.send('Email already exists.')
                return;
            }
            if(!validateEmail(form.email)){
                res.send('Invalid email.')
                return;
            }
        }

        db.set("whitelists", arrayRemove(db.get("whitelists"), form.key));

        var generatedtoken = generateToken();
        var hashedpassword = crypto.createHash('md5').update(`${psw_salt}${form.password}`).digest("hex");
        db.push('account', { uuid: generateUUID(), token: generatedtoken, name: form.uname, email: form.email, password: hashedpassword, premium: 'Basic', mailverified: false, showembed: true });

        const mailOptions = {
            from: 'noreply@celestephoto.com',
            to: form.email,
            subject: 'Account Verification',
            html: `<p>To verify your Celeste account, please click the link below.<br>https://celestephoto.com/v?id=${generatedtoken}</p>`,
        };
        transporter.sendMail(mailOptions, function(err, info) { if (err) { throw err; } });

        res.cookie('token', generatedtoken, { maxAge: 315569260000 })
        res.send('success');
    } else {
       res.send('Username must be alphanumeric.');
    }
});

//---   Upload Server V2.1   ---//
function makefileid(length) {
    const images = db.get('images') || [];
    var result = '';
    var characters = chars;
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    if(images.some(i => i.id.split('.')[0] === result) || result === 'profile') return makefileid(length);
    try {
        if (fs.existsSync('public/content/videos/' + result + '.png')) {
            //console.log(result + '.mp4 exists.');
            return (0)
        } else {
            //console.log(result + '.mp4 doesn\'t exist.');
            return result;
        }
    } catch (err) {
        console.error(err);
    }
}

// Pfp Upload
app.post('/api/pfp', (req, res) => {
    var form = new formidable.IncomingForm();
    form.parse(req, function(err, fields, files) {
        //   ---    Get Sent Token V2.1   ---   //
        const account = db.get("account").find(({ token }) => token === req.cookies.token);
        if (!account) { console.log(`Unauthorized PFP upload request recieved`); return res.status(403).send('Invalid Token'); }

        //Make directory if nonexistant
        if (!fs.existsSync(`public/cdn/${account.uuid}/`)) {
            fs.mkdirSync(`public/cdn/${account.uuid}/`);
        };
        //Parse File
        var filename = files.imgfile.name;
        if(!filename.endsWith('.png')) return res.status(400).send('File must be a PNG!');
        const stats = fs.statSync(files.imgfile.path);
        if((stats.size / (1024 * 1024) > 10)){
            fs.unlinkSync(files.imgfile.path);
            return res.status(400).send('Filesize cannot be greater than 10MB!');
        };
        filename = 'profile.png'
        var newpath = `public/cdn/${account.uuid}/${filename}`;
        fs.renameSync(files.imgfile.path, newpath);
        res.redirect('/dashboard');
    });
});

app.post('/upload', (req, res) => {
    var form = new formidable.IncomingForm();
    form.parse(req, function(err, fields, files) {
        //--    Make Random ID V1   ---   //
        id = makefileid(id_length);
        if (id == 0) {
            do {
                id = makefileid(id_length)
            } while (id == 0);
        }
        //   ---    Get Sent Token V2.1   ---   //
        const account = db.get("account").find(({ token }) => token === req.headers.token);
        if (!account) { console.log(`Unauthorized upload request recieved`); return res.status(403).send('Invalid Token'); }
        if(!account.mailverified) return res.status(403).send('Your account is not verified.');
        if(account.domain && account.domain == "celestephoto.com"){
            let accounts = db.get('account');
            accounts = accounts.filter(function(acc){
                return acc.token !== account.token;
            });
            delete account.domain;
            accounts.push(account);
            db.set('account',accounts);
        };

        //Make directory if nonexistant
        if (!fs.existsSync(`public/cdn/${account.uuid}/`)) {
            fs.mkdirSync(`public/cdn/${account.uuid}/`);
        }
        //Parse File
        if (account.name != undefined) {
            if(!files.imgfile) return res.status(400).send('No imgfile found.');
            var ext = files.imgfile.name.split(".");
            if(!file_extensions.includes(ext[1])) return res.status(400).send('You can only upload media files!');
            const stats = fs.statSync(files.imgfile.path);
            if((stats.size / (1024 * 1024) > 10)){
                fs.unlinkSync(files.imgfile.path);
                return res.status(400).send('Filesize cannot be greater than 10MB!');
            };
            var filename = `${id}.${ext[1]}`
            var newpath = `public/cdn/${account.uuid}/${filename}`;
            fs.rename(files.imgfile.path, newpath, function(err) {
                if (err) throw err;
                db.push('images', {
                    id: `${id}.${ext[1]}`,
                    uuid: account.uuid
                });
                if (!req.headers.json) {
                    console.log(`Username: ${account.name} - Uploading: ${files.imgfile.name} => ${id}.${ext[1]}`);
                    res.writeHead(301, { Location: `https://${account.domain || defaults.domain}/${filename}` });
                    res.end();
                } else {
                    console.log(`Username: ${account.name} - Uploading: ${files.imgfile.name} => ${id}.${ext[1]} --JSON`);
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({ url: `https://${account.domain || defaults.domain}/${filename}` }));
                }



            });
        } else {
            console.log(`Invalid Upload Token: ${token}`)
            res.writeHead(301, { Location: "https://celestephoto.com/login?invalid=token" });
            res.end();
        }

    });
});


app.post('/api/gen/wl', (req, res) => {
    if (req.headers.auth == "1pK0heCC4thNE8hbFM6x") {
        //---   Upload Server V2.1   ---//
        const chars = '0123456789abcdef'
        function genKey(){
            const key = randomString(8, chars) + "-" + randomString(4, chars) + "-" + randomString(4, chars) + "-" + randomString(4, chars);
            if(db.get('whitelists').includes(key)) return genKey();
            return key;
        }
        const key = genKey();
        db.push("whitelists", key)
        res.send(`Invite Generated: ${key}`);
    } else {
        res.send("Denied.");
    }

})

// Functions
const toHTML = function (str = '') {
    str = str.replace(/&/g, "&amp;").replace(/>/g, "&gt;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
    const rex = /[\u{1f300}-\u{1f5ff}\u{1f900}-\u{1f9ff}\u{1f600}-\u{1f64f}\u{1f680}-\u{1f6ff}\u{2600}-\u{26ff}\u{2700}-\u{27bf}\u{1f1e6}-\u{1f1ff}\u{1f191}-\u{1f251}\u{1f004}\u{1f0cf}\u{1f170}-\u{1f171}\u{1f17e}-\u{1f17f}\u{1f18e}\u{3030}\u{2b50}\u{2b55}\u{2934}-\u{2935}\u{2b05}-\u{2b07}\u{2b1b}-\u{2b1c}\u{3297}\u{3299}\u{303d}\u{00a9}\u{00ae}\u{2122}\u{23f3}\u{24c2}\u{23e9}-\u{23ef}\u{25b6}\u{23f8}-\u{23fa}]/ug;
    const updated = str.replace(rex, match => `&#x${match.codePointAt(0).toString(16)};`);
    return updated;
};
  

// Celeste Bot Stuff
function randomString(length, chars) {
    chars = chars || '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}

function generateToken(){
    const token = crypto.createHash('md5').update(`ColourBlind_${randomString(16)}`).digest('hex');
    if(db.get('account').some(u => u.token === token)) return generateToken();
    return token;
};

app.patch('/api/userdata', (req, res) => {
    const { token, auth } = req.query;
    if(auth !== bot_api_key);
    const account = db.get("account").find(u => u.token === req.query.token);
    if(!account) return res.send(JSON.stringify({
        success: false,
        message: 'No account found'
    }));
    const { key, value } = req.body;
    if(!key || !value) return res.send(JSON.stringify({
        success: false,
        message: 'Bad request'
    }));
    account[key] = value;
    accounts = db.get('account').filter(function(acc) {
        return acc.token !== token;
    });
    accounts.push(account);
    db.set('account', accounts);
    return res.send(JSON.stringify({
        success: true,
        message: `Successfully set ${key} to ${value}`
    }));
});

app.get('/api/bot/:method', (req, res) => {
    const account = db.get("account").find(u => u.token === req.query.token);
    if(!account) return res.send(JSON.stringify({
        success: false,
        message: 'No account found'
    }));
    switch(req.params.method){
        case "username":
            res.send(JSON.stringify({
                success: true,
                message: account.name
            }));
        break;

        case "userdata": 
            account.success = true;
            res.send(JSON.stringify(account));
        break;

        case "changename":
            originalName = account.name;
            const { name, auth } = req.query;
            if(auth !== bot_api_key) return res.status(403).send(JSON.stringify({
                success: false,
                message: '403: Unauthorized'
            }));
            alreadyExists = db.get("account").some(u => u.name.toLowerCase() === name.toLowerCase());
            if(alreadyExists) return res.send(JSON.stringify({
                success: false,
                message: 'Username already exists'
            }));
            account.name = name;
            accounts = db.get('account').filter(function(acc) {
                return acc.token !== req.query.token;
            });
            accounts.push(account);
            db.set('account', accounts);
            res.send(JSON.stringify({
                success: true,
                message: 'Successfully changed username'
            }));
        break;

        case "reset":
            const password = randomString(12);
            const hashedpassword = crypto.createHash('md5').update(`${psw_salt}${password}`).digest("hex");
            const token = generateToken();
            account.token = token;
            account.password = hashedpassword;
            accounts = db.get('account').filter(function(acc) {
                return acc.token !== req.query.token;
            });
            accounts.push(account);
            db.set('account', accounts);
            res.send(JSON.stringify({
                username: account.name,
                token: token,
                password: password
            }));
        break;

        default:
            res.status(400).send(JSON.stringify({
                success: false,
                message: 'Unknown method'
            }));
        break;
    };
});



// 404
app.use(function(req, res, next){
    if (req.accepts('html')) {
        res.writeHeader(200, { "Content-Type": "text/html" });
      res.write(`<style>@import url(https://fonts.googleapis.com/css?family=Abel);body{background-color:#111;color:#fff;font-family:Abel}img{max-width:20em;max-height:20em}p{position:absolute;top:20%;right:50%;transform:translateX(50%);font-size:5em}li{display:inline;margin:2em;width:4em;font-size:2em}ul{padding:0;list-style:none;display:table;width:600px;text-align:center;top:55%;right:50%;transform:translateX(50%);position:absolute}li{display:table-cell;position:relative;padding:15px 0;width:3em}a{color:#fff;text-transform:uppercase;text-decoration:none;letter-spacing:.15em;display:inline-block;padding:15px 20px;position:relative}a:after{background:none repeat scroll 0 0 transparent;bottom:0;content:"";display:block;height:2px;left:50%;position:absolute;background:#fff;transition:width .3s ease 0s,left .3s ease 0s;width:0}a:hover:after{width:100%;left:0}@media screen and (max-height:300px){ul{margin-top:40px}}</style><meta property="og:type" content="website"><meta property="og:title" content="404 | Celeste"><meta property="og:description" content="Page not found"><meta property="og:url" content="//celestephoto.com"><title>404 | Page not found</title><link rel="stylesheet" href="/assets/css/404.css"><link rel="icon" href="/assets/images/favicon.png"><center><p>404 | Page not found</p><ul><li><a href="/">Home</a></li><li><a href="/dashboard">Dashboard</a></li><li><a href="/discord">Discord</a></li></ul></center>`)
      res.end();
      return;
    };
    res.status(404);
  
    if (req.accepts('json')) {
      res.send({ error: 404, message: 'Not Found'});
      return;
    }
    res.send('404: Not Found');
  });

// Peacefully close the server on exit
process.on('exit', () => {
    server.close();
});