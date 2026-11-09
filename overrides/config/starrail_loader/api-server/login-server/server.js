const http = require("http");
const https = require("https");
const crypto = require("crypto");
const url = require("url");

const PORT = parseInt(process.env.PORT || "3001", 10);
const AES_IV = Buffer.from("0102030405060708", "utf8");
const SECKEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const NONCE = "0CoJUm6Qyw8W8jud";

// Netease RSA public key modulus
const RSA_MODULUS_HEX = "00e0b5094f668afb6fa31d4038e5b15627015758626efb83d5346a5905812f94d" +
    "0e3f1899660e0afb4cddaf3ce2b0ea2960a59bdb5d9d76cd49dceb0e0fbd0a4d" +
    "21eb32fd0bde96cf9a0cd9f6aacc1efc2e8d0e68be22b19e82e1d84e375f1520f" +
    "2a7a5b880b8b12541a99e9c37bdc77e69a7e5a9a1d0b25d36f53e6a9b7d0d229" +
    "81a4d72e7e7";
const RSA_MODULUS = BigInt("0x" + RSA_MODULUS_HEX);
const RSA_EXPONENT = BigInt("0x010001");

/** BigInt 快速模幂（平方-乘法），弥补 BigInt 没有原生 modPow */
function modPow(base, exponent, modulus) {
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent & 1n) result = (result * base) % modulus;
        exponent >>= 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function createSecretKey(size) {
    let r = "";
    for (let i = 0; i < size; i++) r += SECKEY_CHARS[Math.floor(Math.random() * SECKEY_CHARS.length)];
    return r;
}

/** 单次 AES-128-CBC 加密，返回 base64 */
function aesEncrypt(text, key) {
    const cipher = crypto.createCipheriv("aes-128-cbc", Buffer.from(key, "utf8"), AES_IV);
    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
}

/**
 * weapi 加密（双 AES + 教科书 RSA）
 *
 * 1. 生成 16 位随机 secKey
 * 2. 第一次 AES 用固定 nonce 加密 JSON
 * 3. 第二次 AES 用随机 secKey 加密第一次结果
 * 4. RSA modPow 加密反转后的 secKey，hex 输出补零到 256 位
 */
function weapiEncrypt(jsonData) {
    const secKey = createSecretKey(16);
    // 双 AES
    const firstEncrypted = aesEncrypt(jsonData, NONCE);
    const params = aesEncrypt(firstEncrypted, secKey);
    // 教科书 RSA：BigInt.modPow（非 PKCS1）
    const reversedKey = secKey.split("").reverse().join("");
    const keyHex = Buffer.from(reversedKey, "utf8").toString("hex");
    const keyInt = BigInt("0x" + keyHex);
    const encInt = modPow(keyInt, RSA_EXPONENT, RSA_MODULUS);
    const encSecKey = encInt.toString(16).padStart(256, "0");
    return { params, encSecKey, secKey };
}

function weapiDecrypt(result, secKey) {
    const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(secKey, "utf8"), AES_IV);
    let decrypted = decipher.update(result, "base64", "utf8");
    decrypted += decipher.final("utf8");
    return JSON.parse(decrypted);
}

function sendJson(res, data, statusCode) {
    if (!statusCode) statusCode = 200;
    res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify(data));
}

function weapiPost(apiPath, data, cookies) {
    return new Promise((resolve, reject) => {
        const enc = weapiEncrypt(JSON.stringify(data));
        const body = "params=" + encodeURIComponent(enc.params) + "&encSecKey=" + encodeURIComponent(enc.encSecKey);
        const opts = {
            hostname: "music.163.com", path: apiPath, method: "POST",
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Referer": "https://music.163.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": Buffer.byteLength(body),
                "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9", "Origin": "https://music.163.com"
            }
        };
        if (cookies) opts.headers["Cookie"] = cookies;
        const req = https.request(opts, (res) => {
            let rb = "";
            res.on("data", c => rb += c);
            res.on("end", () => {
                let parsed;
                try { parsed = JSON.parse(rb); } catch(e) { parsed = null; }
                // 如果是 weapi 加密响应（code=200 且有 result 字段），自动解密
                if (parsed && parsed.code === 200 && parsed.result) {
                    try {
                        const decrypted = weapiDecrypt(parsed.result, enc.secKey);
                        console.log("[weapi] " + apiPath + " -> decrypted OK");
                        resolve({ status: res.statusCode, body: decrypted, cookies: res.headers["set-cookie"] || [] });
                        return;
                    } catch (e) {
                        console.log("[weapi] " + apiPath + " decrypt failed: " + e.message);
                    }
                }
                console.log("[weapi] " + apiPath + " -> status=" + res.statusCode + " bodyStart=" + (rb ? rb.substring(0, 80) : "empty"));
                resolve({ status: res.statusCode, body: parsed || rb, cookies: res.headers["set-cookie"] || [] });
            });
        });
        req.setTimeout(15000, () => { req.destroy(); reject(new Error("timeout")); });
        req.on("error", (e) => { console.log("[weapi] " + apiPath + " ERROR: " + e.message); reject(e); });
        req.write(body);
        req.end();
    });
}

let cookieJar = {};
function mergeCookies(newCookies) {
    if (!newCookies) return;
    for (const cs of newCookies) {
        const idx = cs.indexOf("=");
        if (idx > 0) cookieJar[cs.substring(0, idx).trim()] = cs.substring(idx + 1).split(";")[0].trim();
    }
}
function getCookieString() { return Object.entries(cookieJar).map(e => e[0] + "=" + e[1]).join("; "); }
function clearCookies() { cookieJar = {}; }

async function getQrKey() {
    try {
        const r = await weapiPost("/weapi/login/qr/unikey", { time: Date.now() });
        if (r.status !== 200 || !r.body) {
            console.log("[getQrKey] bad response: status=" + r.status + " body=" + (r.body || "empty"));
            return null;
        }
        const d = r.body;
        if (d.code === 200 && d.data && d.data.unikey) return d.data.unikey;
        console.log("[getQrKey] Netease returned code=" + d.code + " " + JSON.stringify(d).substring(0, 100));
        return null;
    } catch (e) {
        console.log("[getQrKey] exception: " + e.message);
        return null;
    }
}

async function createQr(key) {
    try {
        const r = await weapiPost("/weapi/login/qr/create", { key, qrimg: true });
        if (r.status !== 200 || !r.body) {
            console.log("[createQr] bad response: status=" + r.status + " body=" + (r.body || "empty"));
            return null;
        }
        const d = r.body;
        if (d.code === 200 && d.data) return { qrurl: d.data.qrurl, qrimg: d.data.qrimg };
        console.log("[createQr] Netease returned code=" + d.code + " " + JSON.stringify(d).substring(0, 100));
        return null;
    } catch (e) {
        console.log("[createQr] exception: " + e.message);
        return null;
    }
}

async function checkQr(key) {
    try {
        const r = await weapiPost("/weapi/login/qr/check", { key });
        if (!r.body) return { code: -1, message: "网络错误" };
        const d = r.body;
        if (r.cookies) mergeCookies(r.cookies);
        return { code: d.code, message: d.message || "" };
    } catch (e) { return { code: -1, message: "解析失败" }; }
}

async function checkLoginStatus() {
    const cs = getCookieString();
    if (!cs) return null;
    try {
        const r = await weapiPost("/weapi/v1/user/info", {}, cs);
        if (!r.body) return null;
        const d = r.body;
        if (d.code === 200 && d.account && d.profile) return d;
    } catch (e) { }
    return null;
}

// ========== 多平台搜索/歌曲 URL 代理（酷狗、QQ） ==========

/** 通用 HTTP(S) GET 请求，支持重定向，返回解析后的 JSON */
function httpsGet(opts, redirectCount) {
    if (redirectCount === undefined) redirectCount = 0;
    if (redirectCount > 5) return Promise.reject(new Error('too many redirects'));
    return new Promise((resolve, reject) => {
        const mod = opts.port === 80 ? http : https;
        const req = mod.get(opts, (res) => {
            // 处理重定向
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                const redirectUrl = new URL(res.headers.location, `http${opts.port === 443 ? 's' : ''}://${opts.hostname}`);
                const newOpts = {
                    hostname: redirectUrl.hostname,
                    port: redirectUrl.protocol === 'https:' ? 443 : 80,
                    path: redirectUrl.pathname + redirectUrl.search,
                    headers: opts.headers
                };
                req.destroy();
                resolve(httpsGet(newOpts, redirectCount + 1));
                return;
            }
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(new Error('JSON parse: ' + e.message)); }
            });
        });
        req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
        req.end();
    });
}

// ========== 酷狗音乐 ----------

async function searchKugou(keyword, page) {
    const opts = {
        hostname: 'mobilecdn.kugou.com',
        port: 80,
        path: `/api/v3/search/song?format=json&keyword=${encodeURIComponent(keyword)}&page=${page}&pagesize=30&showtype=1`,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Referer': 'http://www.kugou.com/' }
    };
    const raw = await httpsGet(opts);
    if (raw.status !== 1 || !raw.data || !raw.data.info) {
        return { code: 200, result: { songs: [] } };
    }
    const songs = raw.data.info.map(s => ({
        // hash 统一转大写，确保与 gateway API 返回的 hash 大小写一致
        id: ((s.hash || '') + ',' + (s.album_id || '')).toUpperCase(),
        name: s.songname || '',
        artists: [{ name: s.singername || '未知' }],
        album: { name: s.album_name || '', id: String(s.album_id || '') },
        duration: (s.duration || 0) * 1000,
        fee: 0
    }));
    return { code: 200, result: { songs } };
}

async function getKugouSongUrl(id, token, userid) {
    // 解析 id 格式: "hash,album_id" 或 "hash"
    const parts = (id || '').split(',');
    const hash = parts[0];
    const albumId = parts.length > 1 ? parts[1] : '';
    if (!hash) return { code: 200, data: { url: '' } };

    const hasAuth = token && userid;

    // 方法1：尝试 mobile 接口（最可靠，不需要 album_id，但通常不支持 VIP 歌曲）
    try {
        const opts = {
            hostname: 'm.kugou.com',
            port: 80,
            path: `/app/i/getSongInfo.php?cmd=playInfo&hash=${encodeURIComponent(hash)}`,
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Referer': 'http://www.kugou.com/' }
        };
        const raw = await httpsGet(opts);
        if (raw) {
            let url = raw.url || '';
            if (url && !url.startsWith('http')) url = 'http://' + url;
            if (url) return { code: 200, data: { url } };
            console.log('[kugouUrl] mobile no url for hash=' + hash);
        }
    } catch (e) { console.log('[kugouUrl] mobile error: ' + e.message); }

    // 构造认证 Cookie（与 Kugou Web 播放器一致）
    const authCookie = hasAuth
        ? `userid=${userid}; token=${token}; kg_mid=1; kg_dfid=-`
        : '';

    // 方法2：尝试 trackercdn 接口（使用 Cookie 鉴权）
    try {
        const opts2 = {
            hostname: 'trackercdn.kugou.com',
            port: 80,
            path: `/i/v2/?key=${hash}&pid=1&behavior=play&cmd=25&version=8000&timemute=1`,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': 'http://www.kugou.com/',
                'Cookie': authCookie
            }
        };
        const raw2 = await httpsGet(opts2);
        if (raw2 && raw2.status === 1) {
            let url = raw2.url || '';
            if (url && !url.startsWith('http')) url = 'http://' + url;
            if (url) return { code: 200, data: { url } };
        }
    } catch (e) { /* ignore */ }

    // 方法3：尝试 wwwapi 接口（需要 album_id，使用 Cookie 鉴权）
    if (albumId) {
        try {
            const opts3 = {
                hostname: 'wwwapi.kugou.com',
                port: 443,
                path: `/yy/index.php?r=play/getdata&hash=${encodeURIComponent(hash)}&album_id=${encodeURIComponent(albumId)}&mid=1&appid=1014&platid=4`,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Referer': 'https://www.kugou.com/',
                    'Cookie': authCookie
                }
            };
            const raw3 = await httpsGet(opts3);
            if (raw3 && raw3.status === 1 && raw3.data) {
                let url = raw3.data.play_url || '';
                if (url && !url.startsWith('http')) url = 'https://' + url;
                if (url) return { code: 200, data: { url } };
            }
        } catch (e) { /* ignore */ }
    }

    console.log('[kugouUrl] all methods failed for id=' + id);
    return { code: 200, data: { url: '' } };
}

// ---------- QQ 音乐 ----------

async function searchQQ(keyword, page) {
    const opts = {
        hostname: 'c.y.qq.com',
        port: 443,
        path: `/soso/fcgi-bin/client_search_cp?p=${page}&n=30&w=${encodeURIComponent(keyword)}&format=json`,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Referer': 'https://y.qq.com/' }
    };
    const raw = await httpsGet(opts);
    if (raw.code !== 0 || !raw.data || !raw.data.song || !raw.data.song.list) {
        return { code: 200, result: { songs: [] } };
    }
    const songs = raw.data.song.list.map(s => ({
        id: s.songmid || String(s.songid || ''),
        name: s.songname || '',
        artists: (s.singer || []).map(sg => ({ name: sg.name || '未知' })),
        album: { name: s.albumname || '', id: s.albummid || '' },
        duration: (s.interval || 0) * 1000,
        fee: 0
    }));
    return { code: 200, result: { songs } };
}

async function getQQSongUrl(songmid) {
    const data = {
        req_0: {
            module: 'vkey.GetVkeyServer',
            method: 'CgiGetVkey',
            param: { guid: '1000000000', songmid: [songmid], songtype: [0], uin: '0', loginflag: 1, platform: '20' }
        }
    };
    const body = 'format=json&data=' + encodeURIComponent(JSON.stringify(data));
    return new Promise((resolve, reject) => {
        const opts = {
            hostname: 'u.y.qq.com', port: 443, path: '/cgi-bin/musicu.fcg', method: 'POST',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': 'https://y.qq.com/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(body)
            }
        };
        const req = https.request(opts, (res) => {
            let rb = '';
            res.on('data', c => rb += c);
            res.on('end', () => {
                try {
                    const j = JSON.parse(rb);
                    const urls = j.req_0 && j.req_0.data && j.req_0.data.midurlinfo;
                    if (urls && urls.length > 0 && urls[0].purl) {
                        return resolve({ code: 200, data: { url: 'https://dl.stream.qqmusic.qq.com/' + urls[0].purl } });
                    }
                } catch (e) { /* ignore */ }
                resolve({ code: 200, data: { url: '' } });
            });
        });
        req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

// ========== 酷狗音乐用户信息 API（通过 gateway.kugou.com 安卓加密通道） ==========

// 酷狗安卓 RSA 公钥模数（1024 位）
const KG_RSA_MODULUS = BigInt("0x00c8006ed03842d2628209bd314984ca5ed6cfe06e30c95f9d4704d9c49791d7a935ba950ecb0bc8ebf5f5994f0bac927a7eb151b3c1de343303fa539c83136eccfd7d7e511e2dbce18eaa9f784c9b50d443e75865979e0a5e216e46c684066a8d6b998580bbaa22d73f5790286bb14742e83244e44db6d707ffe162c5c7002d45");
// 酷狗安卓签名盐值
const KG_ANDROID_SALT = "OIlwieks28dk2k092lksi2UIkp";
// 酷狗默认 Android 参数
const KG_APPID = 1005;
const KG_CLIENTVER = 20489;

// 酷狗 lite 平台 AES 常量（用于 token 刷新）
const KG_LITE_AES_KEY = 'c24f74ca2820225badc01946dba4fdf7';
const KG_LITE_AES_IV = 'adc01946dba4fdf7';
const KG_LITE_T1_KEY = '5e4ef500e9597fe004bd09a46d8add98';
const KG_LITE_T1_IV = '04bd09a46d8add98';
const KG_LITE_T2_KEY = 'fd14b35e3f81af3817a20ae7adae7020';
const KG_LITE_T2_IV = '17a20ae7adae7020';

/** 酷狗安卓 RSA 加密：将对象 JSON 序列化后转 UTF-8 字节，零填充至 128 字节，BigInt modPow */
function kugouRSAEncrypt(obj) {
    const jsonStr = JSON.stringify(obj);
    const buf = Buffer.from(jsonStr, "utf8");
    // 零填充至 128 字节（1024 位）
    const padded = Buffer.alloc(128, 0);
    buf.copy(padded);
    const hex = padded.toString("hex");
    const m = BigInt("0x" + hex);
    const c = modPow(m, RSA_EXPONENT, KG_RSA_MODULUS);
    return c.toString(16).padStart(256, "0");
}

/** 酷狗安卓签名：MD5(salt + 排序参数 + data + salt) */
function kugouAndroidSignature(params, data) {
    const keys = Object.keys(params).sort();
    const paramStr = keys.map(k => k + "=" + params[k]).join("");
    const md5Input = KG_ANDROID_SALT + paramStr + (data || "") + KG_ANDROID_SALT;
    return crypto.createHash("md5").update(md5Input, "utf8").digest("hex");
}

/** 酷狗 AES-256-CBC 加密（兼容 CryptoJS 行为）
 *  当 opt.key 和 opt.iv 都提供时：直接作为 UTF-8 字节密钥和 IV
 *  否则：MD5(tempKey) 前32字符作为密钥，后16字符作为 IV
 *  返回格式：提供完整 key+iv 时返回 hex 字符串，否则返回 { str: hex, key: tempKey }
 */
function kugouAesEncrypt(data, opt) {
    const input = typeof data === 'object' ? JSON.stringify(data) : String(data);
    let aesKey, aesIv, tempKey = '';
    if (opt && opt.key && opt.iv) {
        aesKey = Buffer.from(opt.key, 'utf8');
        aesIv = Buffer.from(opt.iv, 'utf8');
    } else {
        tempKey = (opt && opt.key) ? opt.key : crypto.randomBytes(8).toString('hex');
        const md5Hex = crypto.createHash('md5').update(tempKey, 'utf8').digest('hex');
        aesKey = Buffer.from(md5Hex.substring(0, 32), 'utf8');
        aesIv = Buffer.from(md5Hex.substring(16), 'utf8');
    }
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, aesIv);
    let encrypted = cipher.update(input, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    if (opt && opt.key && opt.iv) return encrypted;
    return { str: encrypted, key: tempKey };
}

/** 酷狗 AES-256-CBC 解密（兼容 CryptoJS 行为）
 *  密钥推导方式与 kugouAesEncrypt 一致
 */
function kugouAesDecrypt(encryptedHex, tempKey) {
    const md5Hex = crypto.createHash('md5').update(tempKey, 'utf8').digest('hex');
    const aesKey = Buffer.from(md5Hex.substring(0, 32), 'utf8');
    const aesIv = Buffer.from(md5Hex.substring(16), 'utf8');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, aesIv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    try { return JSON.parse(decrypted); } catch (e) { return decrypted; }
}

/** 通过 gateway.kugou.com 获取酷狗用户详情 */
async function getKugouUserDetail(token, userid, dfid) {
    if (!token || !userid) return { status: 1, error_code: 20018, data: null };
    const clienttime = Math.floor(Date.now() / 1000);
    // 构建 RSA 密文 p
    const pk = kugouRSAEncrypt({ token, clienttime }).toUpperCase();
    // 请求体数据
    const data = { visit_time: clienttime, usertype: 1, p: pk, userid: parseInt(userid) };
    const dataStr = JSON.stringify(data);
    // 默认参数
    const params = {
        dfid: dfid || "-", mid: "-", uuid: "-",
        appid: String(KG_APPID), clientver: String(KG_CLIENTVER),
        clienttime: String(clienttime), token, userid: String(userid),
        plat: "1"
    };
    // 生成签名
    params.signature = kugouAndroidSignature(params, dataStr);

    // 构造 URL query string
    const qs = Object.keys(params).map(k => encodeURIComponent(k) + "=" + encodeURIComponent(params[k])).join("&");
    const path = "/v3/get_my_info?" + qs;

    return new Promise((resolve, reject) => {
        const opts = {
            hostname: "gateway.kugou.com", port: 443, path, method: "POST",
            headers: {
                "User-Agent": "Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi",
                "x-router": "usercenter.kugou.com",
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": Buffer.byteLength(dataStr, "utf8"),
                "dfid": "-", clienttime: String(clienttime), mid: "-"
            }
        };
        const req = https.request(opts, (res) => {
            let rb = "";
            res.on("data", c => rb += c);
            res.on("end", () => {
                try {
                    const j = JSON.parse(rb);
                    resolve(j);
                } catch (e) {
                    console.log("[kugouUserDetail] JSON parse error: " + e.message);
                    resolve({ status: 1, error_code: 20018, data: null });
                }
            });
        });
        req.setTimeout(15000, () => { req.destroy(); reject(new Error("timeout")); });
        req.on("error", (e) => { console.log("[kugouUserDetail] ERROR: " + e.message); reject(e); });
        req.write(dataStr);
        req.end();
    });
}

// 酷狗收藏歌单 list_ver 缓存 (listid → version)，用于 collection/add 和 collection/del
// 每次成功操作后更新，确保后续操作使用正确的版本号
const listVerCache = {};

const server = http.createServer(async (req, res) => {
    const p = url.parse(req.url, true);
    console.log(req.method + " " + p.pathname);
    try {
        if (p.pathname === "/health") return sendJson(res, { status: "ok" });
        if (p.pathname === "/login/qr") {
            const key = await getQrKey();
            if (!key) {
                console.log("[login/qr] getQrKey() failed");
                return sendJson(res, { success: false, message: "get unikey failed" });
            }
            console.log("[login/qr] got unikey: " + key);
            const qr = await createQr(key);
            if (!qr) {
                console.log("[login/qr] createQr() failed for key: " + key);
                return sendJson(res, { success: false, message: "create qr failed" });
            }
            console.log("[login/qr] qrurl: " + qr.qrurl.substring(0, 60) + "...");
            return sendJson(res, { success: true, qrurl: qr.qrurl, qrimg: qr.qrimg, state: key });
        }
        if (p.pathname === "/login/qr/check") {
            if (!p.query.state) return sendJson(res, { code: -1, message: "no state" });
            const r = await checkQr(p.query.state);
            let info = null;
            if (r.code === 803) info = await checkLoginStatus();
            return sendJson(res, { code: r.code, message: r.message, account: info, cookie: getCookieString() });
        }
        if (p.pathname === "/login/status") {
            const info = await checkLoginStatus();
            return sendJson(res, info ? { loggedIn: true, profile: info.profile, cookie: getCookieString() } : { loggedIn: false });
        }
        if (p.pathname === "/login/qr/force") {
            try {
                const testKey = await getQrKey();
                return sendJson(res, { success: testKey !== null, key: testKey });
            } catch (e) { return sendJson(res, { success: false, error: e.message }); }
        }
        // 手机号+密码登录
        if (p.pathname === "/login/phone") {
            const phone = p.query.phone;
            const password = p.query.password;
            if (!phone || !password) return sendJson(res, { code: 400, message: "缺少手机号或密码" });
            try {
                const r = await weapiPost("/weapi/login/cellphone", {
                    phone, password, countrycode: p.query.countrycode || "86", rememberLogin: "true"
                });
                if (!r.body) return sendJson(res, { code: -1, message: "网络错误" });
                const d = r.body;
                if (r.cookies) mergeCookies(r.cookies);
                if (d.code === 200) {
                    return sendJson(res, { code: 200, account: d.account, profile: d.profile, cookie: getCookieString() });
                }
                return sendJson(res, d);
            } catch (e) { return sendJson(res, { code: -1, message: e.message }); }
        }
        // 发送手机验证码
        if (p.pathname === "/login/captcha/send") {
            const phone = p.query.phone;
            if (!phone) return sendJson(res, { code: 400, message: "缺少手机号" });
            try {
                const r = await weapiPost("/weapi/sms/captcha/sent", { phone });
                if (!r.body) return sendJson(res, { code: -1, message: "网络错误" });
                const d = r.body;
                return sendJson(res, d);
            } catch (e) { return sendJson(res, { code: -1, message: e.message }); }
        }
        // 手机号+验证码登录
        if (p.pathname === "/login/captcha") {
            const phone = p.query.phone, captcha = p.query.captcha;
            if (!phone || !captcha) return sendJson(res, { code: 400, message: "缺少手机号或验证码" });
            try {
                const r = await weapiPost("/weapi/login/cellphone", {
                    phone, captcha, countrycode: p.query.countrycode || "86"
                });
                if (!r.body) return sendJson(res, { code: -1, message: "网络错误" });
                const d = r.body;
                if (r.cookies) mergeCookies(r.cookies);
                if (d.code === 200) {
                    return sendJson(res, { code: 200, account: d.account, profile: d.profile, cookie: getCookieString() });
                }
                return sendJson(res, d);
            } catch (e) { return sendJson(res, { code: -1, message: e.message }); }
        }
        // ========== 通用 Netease API 代理 ==========
        // POST JSON body: {"path":"/api/v6/playlist/detail","data":{"id":"3778678","n":100,"s":0}}
        if (p.pathname === "/api/netease" && req.method === "POST") {
            let rawBody = "";
            req.on("data", c => rawBody += c);
            req.on("end", async () => {
                try {
                    const { path: apiPath, data: apiData } = JSON.parse(rawBody);
                    if (!apiPath) return sendJson(res, { code: -1, message: "missing path" }, 400);
                    const cs = getCookieString();
                    const r = await weapiPost(apiPath, apiData || {}, cs || undefined);
                    if (r.cookies) mergeCookies(r.cookies);
                    return sendJson(res, r.body || { code: -1, message: "empty response" });
                } catch (e) {
                    return sendJson(res, { code: -1, message: e.message }, 500);
                }
            });
            return;
        }
        // ========== 酷狗音乐搜索 ==========
        if (p.pathname === "/search/kugou") {
            const songs = await searchKugou(p.query.keywords || '', parseInt(p.query.page) || 1);
            return sendJson(res, songs);
        }
        // ========== 酷狗歌单搜索（mobilecdn 公共 API） ==========
        if (p.pathname === "/search/kugou/playlists") {
            try {
                const keyword = p.query.keywords || '';
                const page = parseInt(p.query.page) || 1;
                console.log(`[kugouSearchPlaylists] 搜索歌单: keyword=${keyword} page=${page}`);
                const opts = {
                    hostname: 'mobilecdn.kugou.com',
                    port: 80,
                    path: `/api/v3/search/special?format=json&keyword=${encodeURIComponent(keyword)}&page=${page}&pagesize=20`,
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Referer': 'http://www.kugou.com/' }
                };
                const raw = await httpsGet(opts);
                if (raw && raw.errcode === 0 && raw.data && raw.data.info) {
                    const playlists = raw.data.info.map(s => ({
                        id: String(s.specialid || ''),
                        name: s.specialname || '',
                        trackCount: s.songcount || 0,
                        globalCollectionId: String(s.global_collection_id || ''),
                        list_create_userid: s.list_create_userid || 0,
                        list_create_listid: s.list_create_listid || 0,
                        list_create_gid: s.list_create_gid || '',
                    }));
                    console.log(`[kugouSearchPlaylists] 找到 ${playlists.length} 个歌单`);
                    return sendJson(res, { code: 200, result: { playlists } });
                }
                console.log(`[kugouSearchPlaylists] 无结果: errcode=${raw ? raw.errcode : 'no response'}`);
                return sendJson(res, { code: 200, result: { playlists: [] } });
            } catch (e) {
                console.log(`[kugouSearchPlaylists] 错误: ${e.message}`);
                return sendJson(res, { code: 200, result: { playlists: [] } });
            }
        }
        // ========== 酷狗音乐歌曲 URL ==========
        if (p.pathname === "/song/url/kugou") {
            const result = await getKugouSongUrl(p.query.id || '', p.query.token || '', p.query.userid || '');
            return sendJson(res, result);
        }
        // ========== QQ 音乐搜索 ==========
        if (p.pathname === "/search/qq") {
            const songs = await searchQQ(p.query.keywords || '', parseInt(p.query.page) || 1);
            return sendJson(res, songs);
        }
        // ========== QQ 音乐歌曲 URL ==========
        if (p.pathname === "/song/url/qq") {
            const result = await getQQSongUrl(p.query.id || '');
            return sendJson(res, result);
        }
        // ========== 酷狗用户信息代理 ==========
        if (p.pathname === "/user/kugou") {
            const targetUrl = p.query.url || '';
            if (!targetUrl) return sendJson(res, { error: "no url" }, 400);
            try {
                const parsed = new URL(targetUrl);
                const opts = {
                    hostname: parsed.hostname,
                    port: 443,
                    path: parsed.pathname + parsed.search,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                        'Referer': 'https://www.kugou.com/'
                    }
                };
                https.get(opts, (proxyRes) => {
                    let data = '';
                    proxyRes.on('data', chunk => data += chunk);
                    proxyRes.on('end', () => {
                        try { res.setHeader('Content-Type', 'application/json'); } catch (e) {}
                        res.end(data);
                    });
                }).on('error', (e) => sendJson(res, { error: e.message }, 500));
            } catch (e) { sendJson(res, { error: e.message }, 500); }
            return;
        }
        // ========== 酷狗 Token 刷新（login.user.kugou.com/v5/login_by_token） ==========
        if (p.pathname === "/kugou/login/token") {
            try {
                const userToken = p.query.token || '';
                const userId = p.query.userid || '0';
                if (!userToken || userId === '0') {
                    return sendJson(res, { status: 0, error_code: 20018, error: 'missing token or userid' });
                }

                const dateNow = Date.now();
                const clienttimeSec = Math.floor(dateNow / 1000);
                console.log(`[kugouLoginToken] 刷新token: userId=${userId}`);

                // 1. 加密 token 数据 (p3): AES({clienttime, token}, liteKey+IV)
                const p3 = kugouAesEncrypt(
                    { clienttime: clienttimeSec, token: userToken },
                    { key: KG_LITE_AES_KEY, iv: KG_LITE_AES_IV }
                );

                // 2. 加密空参数 (params): AES({}, randomKey)
                const encryptParams = kugouAesEncrypt({});

                // 3. RSA 加密随机密钥 (pk): RSA({clienttime_ms, key})
                const pk = kugouRSAEncrypt({ clienttime_ms: dateNow, key: encryptParams.key });

                // 4. t1: AES("|" + timestamp, liteT1Key+IV)
                const t1 = kugouAesEncrypt('|' + dateNow, { key: KG_LITE_T1_KEY, iv: KG_LITE_T1_IV });

                // 5. t2: AES("guid|const|mac|dev|time", liteT2Key+IV)
                const guid = crypto.randomUUID ? crypto.randomUUID() : '00000000-0000-0000-0000-000000000000';
                const t2Input = [guid, '0f607264fc6318a92b9e13c65db7cd3c', '', '', dateNow].join('|');
                const t2 = kugouAesEncrypt(t2Input, { key: KG_LITE_T2_KEY, iv: KG_LITE_T2_IV });

                // 6. 构建请求体
                const dataMap = {
                    dfid: p.query.dfid || '-',
                    p3: p3,
                    plat: 1,
                    t1: t1,
                    t2: t2,
                    t3: 'MCwwLDAsMCwwLDAsMCwwLDA=',
                    pk: pk,
                    params: encryptParams.str,
                    userid: parseInt(userId) || 0,
                    clienttime_ms: dateNow,
                };
                const postData = Object.keys(dataMap).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(dataMap[k])}`).join('&');
                console.log(`[kugouLoginToken] POST login.user.kugou.com/v5/login_by_token 参数数=${Object.keys(dataMap).length}`);

                // 7. 发送 POST 请求
                const opts = {
                    hostname: 'login.user.kugou.com',
                    port: 80,
                    path: '/v5/login_by_token',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Content-Length': Buffer.byteLength(postData, 'utf8'),
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                    }
                };
                const mod = http;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[kugouLoginToken] 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前200=${data.substring(0, 200)}`);
                        try {
                            const parsed = JSON.parse(data);
                            if (parsed && parsed.status === 1 && parsed.data) {
                                // 解密 secu_params 获取新 token
                                if (parsed.data.secu_params) {
                                    const decrypted = kugouAesDecrypt(parsed.data.secu_params, encryptParams.key);
                                    console.log(`[kugouLoginToken] secu_params 解密结果: ${JSON.stringify(decrypted).substring(0, 200)}`);
                                    if (typeof decrypted === 'object' && decrypted !== null) {
                                        Object.keys(decrypted).forEach(k => {
                                            parsed.data[k] = decrypted[k];
                                        });
                                    } else if (typeof decrypted === 'string') {
                                        parsed.data.token = decrypted;
                                    }
                                }
                                const result = {
                                    status: 1,
                                    error_code: 0,
                                    data: {
                                        token: parsed.data.token || parsed.data.user_token || '',
                                        userid: String(parsed.data.userid || parsed.data.user_id || '0'),
                                        nickname: parsed.data.nickname || '',
                                        vip_type: parsed.data.vip_type || 0,
                                        grade: parsed.data.grade || parsed.data.vip_type || 0,
                                    }
                                };
                                console.log(`[kugouLoginToken] 刷新成功: token=${result.data.token.substring(0, 16)}... userid=${result.data.userid}`);
                                return sendJson(res, result);
                            }
                            const errCode = parsed && parsed.error_code ? parsed.error_code : (parsed && parsed.status === 0 ? -1 : 0);
                            console.log(`[kugouLoginToken] 刷新失败: status=${parsed ? parsed.status : 'null'} error_code=${errCode}`);
                            return sendJson(res, {
                                status: 0, error_code: errCode || 20018,
                                error: (parsed && parsed.error) || 'token refresh failed',
                                data: null
                            });
                        } catch (e) {
                            console.log(`[kugouLoginToken] JSON解析失败: ${e.message} raw=${data.substring(0, 300)}`);
                            return sendJson(res, { status: 0, error_code: 20018, error: 'parse error: ' + e.message, data: null }, 500);
                        }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error_code: 20018, error: 'timeout' }, 500); });
                req.on('error', (e) => {
                    console.log(`[kugouLoginToken] 请求错误: ${e.message}`);
                    sendJson(res, { status: 0, error_code: 20018, error: e.message }, 500);
                });
                req.write(postData);
                req.end();
                return;
            } catch (e) {
                console.log(`[kugouLoginToken] 整体异常: ${e.message}`);
                return sendJson(res, { status: 0, error_code: 20018, error: e.message }, 500);
            }
        }
        // ========== 酷狗用户信息（通过 gateway.kugou.com 安卓加密通道） ==========
        if (p.pathname === "/kugou/user/detail") {
            try {
                const result = await getKugouUserDetail(p.query.token || '', p.query.userid || '0', p.query.dfid || '');
                return sendJson(res, result);
            } catch (e) {
                return sendJson(res, { status: 1, error_code: 20018, data: null, error: e.message }, 500);
            }
        }
        // ========== 酷狗歌曲 URL（通过 gateway.kugou.com 安卓通道，参考 KuGouMusicApi） ==========
        if (p.pathname === "/kugou/song/url/gateway") {
            try {
                const hash = p.query.hash || '';
                const albumId = p.query.album_id || '';
                const userToken = p.query.token || '';
                const userId = p.query.userid || '0';
                if (!hash) return sendJson(res, { code: 200, data: { url: '' } });

                // 生成设备标识（与 Kugou Android 客户端一致），优先使用客户端传入的 dfid
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const clienttime = Math.floor(Date.now() / 1000);
                const uuid = '-';
                const appid = 1005;
                const clientver = 20489;

                // 计算 key = MD5(hash + "57ae12eb6890223e355ccfcb74edf70d" + appid + mid + userid)
                // 注意: appid 是独立参数，不是 salt 的一部分！
                const KG_KEY_SALT = "57ae12eb6890223e355ccfcb74edf70d";
                const key = crypto.createHash("md5").update(hash + KG_KEY_SALT + appid + mid + (userId || '0')).digest("hex");

                // 构建所有参数（先不包含 signature）
                const params = {
                    dfid, mid, uuid, appid, clientver, clienttime,
                    token: userToken,
                    userid: parseInt(userId) || 0,
                    hash,
                    album_id: parseInt(albumId) || 0,
                    area_code: 1,
                    behavior: 'play',
                    cmd: 26,
                    pid: 2,
                    quality: 128,
                    pidversion: 3001,
                    key,
                    ssa_flag: 'is_fromtrack',
                    module: '',
                    album_audio_id: 0,
                };

                // 生成 signature = MD5("OIlwieks28dk2k092lksi2UIkp" + sorted_params_kv + "OIlwieks28dk2k092lksi2UIkp")
                const KG_SIGN_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const paramsStr = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('');
                const signature = crypto.createHash("md5").update(KG_SIGN_SALT + paramsStr + KG_SIGN_SALT).digest("hex");
                params.signature = signature;

                // 构建完整查询字符串
                const qs = Object.keys(params).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&');
                const gwPath = `/v5/url?${qs}`;

                console.log(`[kugouGateway] 请求 v5/url hash=${hash} key=${key} sig=${signature.substring(0, 8)}... userid=${userId}`);

                // 发送到 gateway.kugou.com/v5/url，x-router: trackercdn.kugou.com
                const result = await new Promise((resolve, reject) => {
                    const opts = {
                        hostname: 'gateway.kugou.com',
                        port: 443,
                        path: gwPath,
                        method: 'GET',
                        headers: {
                            'Host': 'gateway.kugou.com',
                            'x-router': 'trackercdn.kugou.com',
                            'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                            'dfid': dfid,
                            'clienttime': String(clienttime),
                            'mid': mid,
                            'kg-rc': '1',
                            'kg-thash': '5d816a0',
                            'kg-rec': '1',
                            'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                        }
                    };
                    const mod = require('https');
                    const req = mod.get(opts, (res) => {
                        let data = '';
                        res.on('data', c => data += c);
                        res.on('end', () => {
                            try { resolve(JSON.parse(data)); }
                            catch (e) { reject(new Error('JSON parse: ' + e.message + ' raw: ' + data.substring(0, 200))); }
                        });
                    });
                    req.setTimeout(15000, () => { req.destroy(); reject(new Error('timeout')); });
                    req.on('error', reject);
                    req.end();
                });

                if (result && result.status === 1 && result.url) {
                    let url = '';
                    if (Array.isArray(result.url)) {
                        url = result.url[0] || '';
                    } else {
                        url = result.url || '';
                    }
                    // 如果主 URL 为空或不是 http 开头，尝试 backupUrl
                    if ((!url || !url.startsWith('http')) && result.backupUrl) {
                        if (Array.isArray(result.backupUrl)) {
                            url = result.backupUrl[0] || '';
                        } else {
                            url = result.backupUrl || '';
                        }
                    }
                    if (url && !url.startsWith('http')) url = 'https://' + url;
                    if (url) {
                        console.log(`[kugouGateway] 成功 hash=${hash} ext=${result.extName || '?'} priv=${result.priv_status}`);
                        // 返回完整信息供 Java 端诊断
                        return sendJson(res, { code: 200, data: { url, extName: result.extName || '', privStatus: result.priv_status } });
                    }
                }
                console.log(`[kugouGateway] 无URL hash=${hash} status=${result ? result.status : 'null'} priv=${result ? result.priv_status : 'null'} err_code=${result ? (result.error_code || result.err_code || 'none') : 'null'}`);
                return sendJson(res, { code: 200, data: { url: '' } });
            } catch (e) {
                console.log(`[kugouGateway] 失败: ${e.message}`);
                return sendJson(res, { code: 200, data: { url: '' } });
            }
        }
        // ========== 酷狗 Gateway 安卓通道通用调用 ==========
        if (p.pathname === "/kugou/gateway/call") {
            try {
                const { router, path: gwPath, method, data: dataStr } = p.query;
                console.log(`[MARKER-E1] /kugou/gateway/call 收到: router=${router} gwPath=${gwPath} method=${method || 'GET'} hasData=${!!dataStr}`);
                if (!router || !gwPath) {
                    console.log(`[MARKER-E2] 缺少必要参数 router=${router} gwPath=${gwPath}`);
                    return sendJson(res, { status: 0, error: 'missing router or path' });
                }

                const userToken = p.query.token || '';
                const userId = p.query.userid || '0';
                const clienttime = Math.floor(Date.now() / 1000);
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const appid = 1005;
                const clientver = 20489;
                const uuid = '-';
                const KG_ANDROID_SALT = "OIlwieks28dk2k092lksi2UIkp";

                // 构建业务参数（从查询参数中排除控制参数）
                const extraParams = { ...p.query };
                delete extraParams.router; delete extraParams.path; delete extraParams.method; delete extraParams.data;

                console.log(`[MARKER-E3] 业务参数: ${JSON.stringify(extraParams)}`);

                // 构建完整参数（默认参数 + 业务参数）
                const allParams = {
                    dfid, mid, uuid, appid, clientver, clienttime,
                    ...(userToken ? { token: userToken } : {}),
                    ...(userId !== '0' ? { userid: parseInt(userId) } : {}),
                    ...extraParams
                };

                // Android 签名: MD5(salt + sorted_k=v + data + salt)
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${typeof allParams[k] === 'object' ? JSON.stringify(allParams[k]) : allParams[k]}`).join('');
                const signature = crypto.createHash("md5").update(KG_ANDROID_SALT + paramStr + (dataStr || '') + KG_ANDROID_SALT).digest("hex");
                allParams.signature = signature;

                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                const fullPath = `${gwPath}?${qs}`;
                const httpMethod = (method || 'GET').toUpperCase();

                console.log(`[MARKER-E4] 请求 gateway.kugou.com: method=${httpMethod} fullPath=${fullPath.substring(0, 200)}`);
                console.log(`[MARKER-E5] 请求 gateway.kugou.com: x-router=${router} appid=${appid} clientver=${clientver}`);

                const opts = {
                    hostname: 'gateway.kugou.com',
                    port: 443,
                    path: fullPath,
                    method: httpMethod,
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'x-router': router,
                        'dfid': dfid,
                        'clienttime': String(clienttime),
                        'mid': mid,
                        'kg-rc': '1',
                        'kg-thash': '5d816a0',
                        'kg-rec': '1',
                        'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                    }
                };

                const mod = https;
                // 修复: 使用 request() 而不是 get() 以支持 POST 方法
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[MARKER-E6] gateway 响应: statusCode=${apiRes.statusCode} 长度=${data.length}`);
                        try { return sendJson(res, JSON.parse(data)); }
                        catch (e) {
                            console.log(`[MARKER-E7] gateway 响应 JSON 解析失败: ${e.message} raw=${data.substring(0, 300)}`);
                            return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) });
                        }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); console.log(`[MARKER-E8] gateway 请求超时`); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { console.log(`[MARKER-E9] gateway 请求错误: ${e.message}`); sendJson(res, { status: 0, error: e.message }, 500); });
                if (dataStr && httpMethod === 'POST') {
                    console.log(`[MARKER-E10] 发送POST数据: ${dataStr}`);
                    req.write(dataStr);
                }
                req.end();
            } catch (e) {
                console.log(`[MARKER-E11] /kugou/gateway/call 异常: ${e.message}`);
                sendJson(res, { status: 0, error: e.message }, 500);
            }
            return;
        }
        // ========== 酷狗 Gateway 收藏歌曲到默认歌单（add_song） ==========
        // 通过 gateway add_song API 将歌曲添加到"我喜欢的音乐"歌单
        if (p.pathname === "/kugou/gateway/collection/add") {
            try {
                const { hash, album_id, name, listid, gcid, token, userid } = p.query;
                if (!hash || !listid || !token || !userid) {
                    return sendJson(res, { status: 0, error: 'missing required params (hash, listid, token, userid)' });
                }
                const clienttime = Math.floor(Date.now() / 1000);
                const dataMap = {
                    userid: parseInt(userid),
                    token,
                    listid: parseInt(listid),
                    type: 0,
                    slow_upload: 1,
                    scene: "false;null",
                    // data 必须是数组（不是 JSON 字符串），整个 dataMap 会被外层 JSON.stringify
                    data: [{ number: 1, name: name || '', hash, size: 0, sort: 0, timelen: 0, bitrate: 0, album_id: parseInt(album_id || 0), mixsongid: 0 }]
                };
                // 使用缓存的 list_ver 而不是硬编码的 0
                const cachedVer = listVerCache[listid];
                if (cachedVer !== undefined) {
                    dataMap.list_ver = cachedVer;
                    console.log(`[collection/add] 使用缓存 list_ver=${cachedVer} listid=${listid}`);
                } else {
                    dataMap.list_ver = 0;
                    console.log(`[collection/add] 无缓存 list_ver，使用默认值 0 listid=${listid}`);
                }
                // 如果有 gcid(global_collection_id)，也传入（某些 API 版本需要）
                if (gcid) {
                    dataMap.global_collection_id = gcid;
                }
                const dataJson = JSON.stringify(dataMap);
                const extraParams = { last_time: clienttime, last_area: 'gztx', userid: parseInt(userid), token };
                // 重新构建带签名和默认参数的请求
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const allParams = {
                    dfid, mid, uuid: '-', appid: 1005, clientver: 20489, clienttime,
                    ...extraParams
                };
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const KG_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const signature = crypto.createHash("md5").update(KG_SALT + paramStr + dataJson + KG_SALT).digest("hex");
                allParams.signature = signature;
                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                // 注意: add_song 需要使用 /cloudlist.service/v6/add_song 路径（含 service 前缀）
                // 与 delete_songs(/v4/delete_songs + x-router) 不同
                const fullPath = `/cloudlist.service/v6/add_song?${qs}`;
                const opts = {
                    hostname: 'gateway.kugou.com', port: 443, path: fullPath, method: 'POST',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        // add_song 不需要 x-router 头，路径已包含 cloudlist.service
                        'dfid': dfid, 'clienttime': String(clienttime), 'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                        'Content-Type': 'application/json; charset=utf-8'
                    }
                };
                const mod = https;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[collection/add] gateway 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前300=${data.substring(0, 300)}`);
                        try {
                            const parsed = JSON.parse(data);
                            // 成功时缓存 list_ver（从 data 中的 status/pre_list_ver 推断）
                            if (parsed && parsed.data) {
                                const pd = parsed.data;
                                if (pd.pre_list_ver !== undefined && pd.status === 1) {
                                    const newVer = pd.pre_list_ver + 1;
                                    listVerCache[listid] = newVer;
                                    console.log(`[collection/add] 更新 listVerCache[${listid}]=${newVer} (from pre_list_ver ${pd.pre_list_ver})`);
                                } else if (pd.list_ver !== undefined) {
                                    listVerCache[listid] = pd.list_ver;
                                    console.log(`[collection/add] 更新 listVerCache[${listid}]=${pd.list_ver}`);
                                }
                            }
                            return sendJson(res, parsed);
                        }
                        catch (e) { return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) }); }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { sendJson(res, { status: 0, error: e.message }, 500); });
                req.write(dataJson);
                req.end();
            } catch (e) { sendJson(res, { status: 0, error: e.message }, 500); }
            return;
        }

        // ========== 酷狗 Gateway 从默认歌单删除歌曲（delete_songs） ==========
        // 通过 gateway delete_songs API 从"我喜欢的音乐"歌单删除歌曲
        if (p.pathname === "/kugou/gateway/collection/del") {
            try {
                const { fileid, listid, token, userid } = p.query;
                if (!fileid || !listid || !token || !userid) {
                    return sendJson(res, { status: 0, error: 'missing required params (fileid, listid, token, userid)' });
                }
                const dataMap = {
                    listid: parseInt(listid),
                    userid: parseInt(userid),
                    data: [{ fileid: parseInt(fileid) }],
                    type: 0,
                    token,
                };
                // 使用缓存的 list_ver 而不是硬编码的 0
                const cachedDelVer = listVerCache[listid];
                if (cachedDelVer !== undefined) {
                    dataMap.list_ver = cachedDelVer;
                    console.log(`[collection/del] 使用缓存 list_ver=${cachedDelVer} listid=${listid}`);
                } else {
                    dataMap.list_ver = 0;
                    console.log(`[collection/del] 无缓存 list_ver，使用默认值 0 listid=${listid}`);
                }
                const dataJson = JSON.stringify(dataMap);
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const clienttime = Math.floor(Date.now() / 1000);
                const allParams = {
                    dfid, mid, uuid: '-', appid: 1005, clientver: 20489, clienttime,
                };
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const KG_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const signature = crypto.createHash("md5").update(KG_SALT + paramStr + dataJson + KG_SALT).digest("hex");
                allParams.signature = signature;
                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                const fullPath = `/v4/delete_songs?${qs}`;
                const opts = {
                    hostname: 'gateway.kugou.com', port: 443, path: fullPath, method: 'POST',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'x-router': 'cloudlist.service.kugou.com',
                        'dfid': dfid, 'clienttime': String(clienttime), 'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                        'Content-Type': 'application/json; charset=utf-8'
                    }
                };
                const mod = https;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[collection/del] gateway 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前300=${data.substring(0, 300)}`);
                        try {
                            const parsed = JSON.parse(data);
                            // 成功时缓存 list_ver（从 data.pre_list_ver 推断新版本）
                            if (parsed && parsed.data && parsed.data.status === 1 && parsed.data.pre_list_ver !== undefined) {
                                const newVer = parsed.data.pre_list_ver + 1;
                                listVerCache[listid] = newVer;
                                console.log(`[collection/del] 更新 listVerCache[${listid}]=${newVer} (from pre_list_ver ${parsed.data.pre_list_ver})`);
                            }
                            return sendJson(res, parsed);
                        }
                        catch (e) { return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) }); }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { sendJson(res, { status: 0, error: e.message }, 500); });
                req.write(dataJson);
                req.end();
            } catch (e) { sendJson(res, { status: 0, error: e.message }, 500); }
            return;
        }

        // ========== 酷狗 Gateway 收藏歌单（add_list） ==========
        if (p.pathname === "/kugou/gateway/playlist/sub") {
            try {
                const { name, list_create_userid, list_create_listid, list_create_gid, token, userid } = p.query;
                if (!name || !list_create_userid || !list_create_listid || !token || !userid) {
                    return sendJson(res, { status: 0, error: 'missing required params' });
                }
                const clienttime = Math.floor(Date.now() / 1000);
                const dataMap = {
                    userid: parseInt(userid), token, total_ver: 0, name, type: 1, source: 1,
                    is_pri: 0, list_create_userid: parseInt(list_create_userid),
                    list_create_listid: parseInt(list_create_listid),
                    list_create_gid: list_create_gid || '', from_shupinmv: 0,
                };
                const dataJson = JSON.stringify(dataMap);
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const allParams = {
                    dfid, mid, uuid: '-', appid: 1005, clientver: 20489, clienttime,
                    userid: parseInt(userid), token,
                };
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const KG_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const signature = crypto.createHash("md5").update(KG_SALT + paramStr + dataJson + KG_SALT).digest("hex");
                allParams.signature = signature;
                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                console.log(`[playlist/sub] 请求参数: allParams=${JSON.stringify(allParams)} dataMap=${JSON.stringify(dataMap)}`);
                const fullPath = `/cloudlist.service/v5/add_list?${qs}`;
                console.log(`[playlist/sub] 完整路径: ${fullPath.substring(0, 300)}`);
                const opts = {
                    hostname: 'gateway.kugou.com', port: 443, path: fullPath, method: 'POST',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'dfid': dfid, 'clienttime': String(clienttime), 'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                        'Content-Type': 'application/json; charset=utf-8'
                    }
                };
                const mod = https;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[playlist/sub] gateway 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前300=${data.substring(0, 300)}`);
                        try { return sendJson(res, JSON.parse(data)); }
                        catch (e) { return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) }); }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { sendJson(res, { status: 0, error: e.message }, 500); });
                req.write(dataJson);
                req.end();
            } catch (e) { sendJson(res, { status: 0, error: e.message }, 500); }
            return;
        }

        // ========== 酷狗 Gateway 取消收藏歌单（delete_list，需 AES + RSA 加密） ==========
        if (p.pathname === "/kugou/gateway/playlist/unsub") {
            try {
                const { listid, token, userid } = p.query;
                if (!listid || !token || !userid) {
                    return sendJson(res, { status: 0, error: 'missing required params (listid, token, userid)' });
                }
                const clienttime = Math.floor(Date.now() / 1000);
                // 1. AES 加密请求体
                const aesData = JSON.stringify({ listid: parseInt(listid), total_ver: 0, type: 1 });
                const randKey = Array.from({length: 6}, () => '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'.charAt(Math.floor(Math.random() * 36))).join('').toLowerCase();
                const md5Key = crypto.createHash("md5").update(randKey).digest("hex");
                const aesKey = md5Key.substring(0, 16);
                const aesIv = md5Key.substring(16, 32);
                const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(aesKey), Buffer.from(aesIv));
                let encrypted = cipher.update(aesData, 'utf8', 'base64');
                encrypted += cipher.final('base64');
                // 2. RSA 加密 AES 密钥: rsaEncrypt2({aes: randKey, uid: userid, token})
                const rsaData = JSON.stringify({ aes: randKey, uid: parseInt(userid), token });
                const rsaPubKey = `-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIAG7QOELSYoIJvTFJhMpe1s/gbjDJX51HBNnEl5HXqTW6lQ7LC8jr9fWZTwusknp+sVGzwd40MwP6U5yDE27M/X1+UR4tvOGOqp94TJtQ1EPnWGWXngpeIW5GxoQGao1rmYWAu6oi1z9XkChrsUdC6DJE5E221wf/4WLFxwAtRQIDAQAB\n-----END PUBLIC KEY-----`;
                const pVal = crypto.publicEncrypt({
                    key: rsaPubKey,
                    padding: crypto.constants.RSA_PKCS1_PADDING
                }, Buffer.from(rsaData, 'utf8')).toString('hex').toUpperCase();
                // 3. 构建签名参数
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const signKey = crypto.createHash("md5").update(`1005OIlwieks28dk2k092lksi2UIkp20489${clienttime}`).digest("hex");
                const allParams = {
                    dfid, mid, uuid: '-', appid: 1005, clientver: 20489, clienttime,
                    key: signKey, last_area: 'gztx', last_time: clienttime, p: pVal,
                };
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const KG_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const signature = crypto.createHash("md5").update(KG_SALT + paramStr + encrypted + KG_SALT).digest("hex");
                allParams.signature = signature;
                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                const fullPath = `/v2/delete_list?${qs}`;
                const opts = {
                    hostname: 'gateway.kugou.com', port: 443, path: fullPath, method: 'POST',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'x-router': 'cloudlist.service.kugou.com',
                        'dfid': dfid, 'clienttime': String(clienttime), 'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                        'Content-Type': 'text/plain; charset=utf-8'
                    }
                };
                const mod = https;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[playlist/unsub] gateway 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前200=${data.substring(0, 200)}`);
                        // delete_list 返回 AES 加密的 arraybuffer，需要解密
                        try {
                            // 先尝试直接 JSON 解析（可能返回错误）
                            const parsed = JSON.parse(data);
                            return sendJson(res, parsed);
                        } catch (e) {
                            // AES 解密响应
                            try {
                                const decryptKey = md5Key.substring(0, 16);
                                const decryptIv = md5Key.substring(16, 32);
                                const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(decryptKey), Buffer.from(decryptIv));
                                let decrypted = decipher.update(data, 'base64', 'utf8');
                                decrypted += decipher.final('utf8');
                                const result = JSON.parse(decrypted);
                                return sendJson(res, { status: 1, data: result });
                            } catch (e2) {
                                return sendJson(res, { status: 0, error: 'parse error: ' + e2.message, raw: data.substring(0, 500) });
                            }
                        }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { sendJson(res, { status: 0, error: e.message }, 500); });
                req.write(encrypted);
                req.end();
            } catch (e) { sendJson(res, { status: 0, error: e.message }, 500); }
            return;
        }

        if (p.pathname === "/kugou/gateway/user/playlists") {
            try {
                const userToken = p.query.token || '';
                const userId = p.query.userid || '0';
                console.log(`[MARKER-F1] /kugou/gateway/user/playlists 收到: token=${!!userToken} userId=${userId}`);
                if (!userToken || userId === '0') {
                    console.log(`[MARKER-F2] 未登录, 返回空`);
                    return sendJson(res, { status: 0, error: 'not logged in' });
                }

                const clienttime = Math.floor(Date.now() / 1000);
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const appid = 1005;
                const clientver = 20489;
                const uuid = '-';
                const KG_ANDROID_SALT = "OIlwieks28dk2k092lksi2UIkp";

                // 请求体数据
                const dataMap = {
                    userid: parseInt(userId),
                    token: userToken,
                    total_ver: 979,
                    type: parseInt(p.query.type || '0'),
                    page: parseInt(p.query.page || '1'),
                    pagesize: parseInt(p.query.pagesize || '100'),
                };
                const dataStr = JSON.stringify(dataMap);
                console.log(`[MARKER-F3] POST body: ${dataStr}`);

                // 构建 URL 参数
                const urlParams = { plat: 1, userid: parseInt(userId), token: userToken };

                // 完整参数
                const allParams = {
                    dfid, mid, uuid, appid, clientver, clienttime,
                    ...urlParams,
                };

                // Android 签名: MD5(salt + sorted_k=v + data + salt)
                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const signature = crypto.createHash("md5").update(KG_ANDROID_SALT + paramStr + dataStr + KG_ANDROID_SALT).digest("hex");
                allParams.signature = signature;

                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                const fullPath = `/v7/get_all_list?${qs}`;

                console.log(`[MARKER-F4] POST 到 gateway.kugou.com/v7/get_all_list`);
                console.log(`[MARKER-F5] 参数(不包含qs): ${JSON.stringify(Object.keys(allParams))}`);

                const opts = {
                    hostname: 'gateway.kugou.com',
                    port: 443,
                    path: fullPath,
                    method: 'POST',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'x-router': 'cloudlist.service.kugou.com',
                        'Content-Type': 'application/json; charset=utf-8',
                        'Content-Length': Buffer.byteLength(dataStr, 'utf8'),
                        'dfid': dfid,
                        'clienttime': String(clienttime),
                        'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                    }
                };

                const req = https.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[MARKER-F6] gateway 用户歌单响应: statusCode=${apiRes.statusCode} 长度=${data.length}`);
                        console.log(`[MARKER-F7] 响应预览: ${data.substring(0, 300)}`);
                        try { return sendJson(res, JSON.parse(data)); }
                        catch (e) {
                            console.log(`[MARKER-F8] JSON 解析失败: ${e.message}`);
                            return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) });
                        }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); console.log(`[MARKER-F9] 用户歌单请求超时`); sendJson(res, { status: 0, error: 'timeout' }, 500); });
                req.on('error', (e) => { console.log(`[MARKER-F10] 用户歌单请求错误: ${e.message}`); sendJson(res, { status: 0, error: e.message }, 500); });
                req.write(dataStr);
                req.end();
            } catch (e) {
                console.log(`[MARKER-F11] /kugou/gateway/user/playlists 异常: ${e.message}`);
                sendJson(res, { status: 0, error: e.message }, 500);
            }
            return;
        }
        // ========== 酷狗 Gateway 歌单歌曲列表（安卓通道） ==========
        if (p.pathname === "/kugou/gateway/playlist/songs") {
            try {
                const clienttime = Math.floor(Date.now() / 1000);
                const mid = crypto.createHash("md5").update("musicbridge_kugou_device", "utf8").digest("hex");
                const dfid = p.query.dfid || crypto.randomBytes(12).toString('hex');
                const appid = 1005;
                const clientver = 20489;
                const uuid = '-';
                const KG_ANDROID_SALT = "OIlwieks28dk2k092lksi2UIkp";
                const pageSize = parseInt(p.query.pagesize || '300');
                const page = parseInt(p.query.page || '1');
                // 支持直接传入 begin_idx (优先级高于 page)，用于分页
                const beginIdx = p.query.begin_idx !== undefined ? parseInt(p.query.begin_idx) : (page - 1) * pageSize;

                const playlistId = p.query.id || '';
                console.log(`[MARKER-G1] /kugou/gateway/playlist/songs 收到: id=${playlistId} page=${page} pageSize=${pageSize} begin_idx=${beginIdx}`);

                const allParams = {
                    dfid, mid, uuid, appid, clientver, clienttime,
                    area_code: 1,
                    begin_idx: beginIdx,
                    plat: 1,
                    type: 1,
                    mode: 1,
                    personal_switch: 1,
                    extend_fields: 'abtags,hot_cmt,popularization',
                    pagesize: pageSize,
                    global_collection_id: playlistId,
                };

                console.log(`[MARKER-G2] 使用 global_collection_id=${playlistId}`);

                const sortedKeys = Object.keys(allParams).sort();
                const paramStr = sortedKeys.map(k => `${k}=${allParams[k]}`).join('');
                const signature = crypto.createHash("md5").update(KG_ANDROID_SALT + paramStr + '' + KG_ANDROID_SALT).digest("hex");
                allParams.signature = signature;

                const qs = Object.keys(allParams).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`).join('&');
                const fullPath = `/pubsongs/v2/get_other_list_file_nofilt?${qs}`;

                console.log(`[MARKER-G3] 请求 gateway.kugou.com/pubsongs/v2/get_other_list_file_nofilt`);

                const opts = {
                    hostname: 'gateway.kugou.com',
                    port: 443,
                    path: fullPath,
                    method: 'GET',
                    headers: {
                        'User-Agent': 'Android15-1070-11083-46-0-DiscoveryDRADProtocol-wifi',
                        'dfid': dfid, 'clienttime': String(clienttime), 'mid': mid,
                        'kg-rc': '1', 'kg-thash': '5d816a0', 'kg-rec': '1', 'kg-rf': 'B9EDA08A64250DEFFBCADDEE00F8F25F',
                    }
                };

                https.get(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[MARKER-G4] gateway 歌单歌曲响应: statusCode=${apiRes.statusCode} 长度=${data.length}`);
                        console.log(`[MARKER-G5] 响应预览: ${data.substring(0, 300)}`);
                        try {
                            const parsed = JSON.parse(data);
                            // 从响应 data 中提取 list_ver 并缓存（用于后续 collection/add/del 操作）
                            if (parsed && parsed.data) {
                                const pd = parsed.data;
                                // list_ver 可能在 data 顶层，也可能在 data.info/0 中
                                if (pd.list_ver !== undefined) {
                                    listVerCache[playlistId] = pd.list_ver;
                                    console.log(`[MARKER-G4-cache] 缓存 listVerCache[${playlistId}]=${pd.list_ver}`);
                                } else if (pd.pre_list_ver !== undefined) {
                                    listVerCache[playlistId] = pd.pre_list_ver;
                                    console.log(`[MARKER-G4-cache] 缓存 listVerCache[${playlistId}]=${pd.pre_list_ver} (from pre_list_ver)`);
                                }
                                // 如果 data 中有 listid，也以 listid 为键缓存（后续 collection 操作使用 listid）
                                if (pd.listid !== undefined) {
                                    const listidStr = String(pd.listid);
                                    if (!listVerCache[listidStr]) {
                                        listVerCache[listidStr] = listVerCache[playlistId];
                                        console.log(`[MARKER-G4-cache] 同步 listVerCache[${listidStr}]=${listVerCache[playlistId]}`);
                                    }
                                }
                            }
                            return sendJson(res, parsed);
                        }
                        catch (e) {
                            console.log(`[MARKER-G6] JSON 解析失败: ${e.message} raw=${data.substring(0, 200)}`);
                            return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) });
                        }
                    });
                }).on('error', (e) => {
                    console.log(`[MARKER-G7] gateway 歌单歌曲错误: ${e.message}`);
                    sendJson(res, { status: 0, error: e.message }, 500);
                });
            } catch (e) {
                console.log(`[MARKER-G8] /kugou/gateway/playlist/songs 异常: ${e.message}`);
                sendJson(res, { status: 0, error: e.message }, 500);
            }
            return;
        }
        // ========== 酷狗 获取歌单详情（用于收藏歌单时获取创建者信息） ==========
        // 使用 m.kugou.com 公共 API（HTTP 80，无需认证），替代已失效的 gateway v3/get_list_info
        if (p.pathname === "/kugou/gateway/playlist/info") {
            try {
                const { gcid } = p.query;
                if (!gcid) {
                    return sendJson(res, { status: 0, error: 'missing gcid' });
                }
                // 提取纯数字 specialid（兼容 global_collection_id 格式和纯数字格式）
                let specialId = gcid;
                const match = gcid.match(/\d+/);
                if (match) specialId = match[0];
                console.log(`[playlist/info] 使用 m.kugou.com 获取歌单详情: specialId=${specialId}`);
                const opts = {
                    hostname: 'm.kugou.com',
                    port: 80,
                    path: `/plist/list/${encodeURIComponent(specialId)}?json=true`,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                        'Referer': 'http://www.kugou.com/'
                    }
                };
                const mod = http;
                const req = mod.request(opts, (apiRes) => {
                    let data = '';
                    apiRes.on('data', c => data += c);
                    apiRes.on('end', () => {
                        console.log(`[playlist/info] m.kugou.com 响应: statusCode=${apiRes.statusCode} 长度=${data.length} 前500=${data.substring(0, 500)}`);
                        try {
                            const json = JSON.parse(data);
                            if (json && json.plist) {
                                const pl = json.plist;
                                // 统一返回格式，兼容 Java 端的 data.isJsonArray() 和 data.isJsonObject() 两种判断
                                const result = {
                                    status: 1,
                                    error_code: 0,
                                    data: [{
                                        list_create_userid: pl.userid || 0,
                                        list_create_listid: pl.specialid || parseInt(specialId) || 0,
                                        list_create_gid: pl.global_collection_id || '',
                                        name: pl.specialname || pl.name || '',
                                        track_count: pl.songcount || 0,
                                    }]
                                };
                                return sendJson(res, result);
                            }
                            return sendJson(res, { status: 0, error_code: -1, data: [], error: 'no plist in response' });
                        } catch (e) {
                            return sendJson(res, { status: 0, error_code: -1, data: [], error: 'parse error: ' + e.message, raw: data.substring(0, 500) });
                        }
                    });
                });
                req.setTimeout(15000, () => { req.destroy(); sendJson(res, { status: 0, error_code: -1, data: [], error: 'timeout' }, 500); });
                req.on('error', (e) => { sendJson(res, { status: 0, error_code: -1, data: [], error: e.message }, 500); });
                req.end();
            } catch (e) { sendJson(res, { status: 0, error_code: -1, data: [], error: e.message }, 500); }
            return;
        }
        // ========== 酷狗 Web API 通用代理（KG_WEB_SALT 签名，用于 www.kugou.com/yy/index.php） ==========
        if (p.pathname === "/kugou/web-api") {
            try {
                const KG_WEB_SALT = "NVPh5oo715z5DIWAeQlhMDsWXXQV4hwt";
                const params = { ...p.query };

                // 计算签名: MD5(salt + sorted_k=v + salt)
                const sortedKeys = Object.keys(params).sort();
                const sigStr = sortedKeys.map(k => `${k}=${params[k]}`).join('');
                const signature = crypto.createHash("md5").update(KG_WEB_SALT + sigStr + KG_WEB_SALT).digest("hex");
                params.signature = signature;

                // 重新构造带 signature 的 query string
                const allKeys = Object.keys(params).sort();
                const qs = allKeys.map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&');
                const webUrl = `https://www.kugou.com/yy/index.php?${qs}`;

                console.log(`[kugouWebApi] 请求 r=${p.query.r || '?'} 参数数=${allKeys.length}`);

                // 使用固定 kg_mid（首次随机生成后保持一致性，避免被 WAF 拦截）
                if (typeof global._kgMid === 'undefined') {
                    global._kgMid = crypto.createHash('md5').update(
                        Array.from({length: 32}, () => Math.floor(Math.random() * 16).toString(16)).join('')
                    ).digest('hex');
                }
                const kgMid = global._kgMid;

                // 先用 HTTPS 请求，如果失败再用 HTTP
                const tryRequest = (useHttps) => {
                    const mod = useHttps ? https : http;
                    const proto = useHttps ? 'https' : 'http';
                    const tryUrl = webUrl.replace('https://', proto + '://');
                    const agent = new mod.Agent({ keepAlive: true });

                    mod.get(tryUrl, {
                        agent,
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                            'Referer': 'https://www.kugou.com/',
                            'Cookie': 'kg_mid=' + kgMid + '; kg_dfid=' + kgMid.substring(0, 24) + ';',
                            'Accept': 'application/json, text/plain, */*',
                            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                            'Accept-Encoding': 'gzip, deflate',
                            'Sec-Fetch-Dest': 'empty',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-origin',
                            'x-requested-with': 'XMLHttpRequest'
                        }
                    }, (apiRes) => {
                        // 处理 301/302 重定向
                        if (apiRes.statusCode === 301 || apiRes.statusCode === 302) {
                            const location = apiRes.headers['location'];
                            if (location) {
                                console.log(`[kugouWebApi] 收到 ${apiRes.statusCode} 重定向到 ${location}`);
                                // 跟随重定向，使用 Location 中的新 URL
                                const followMod = location.startsWith('https') ? https : http;
                                followMod.get(location, {
                                    headers: {
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                                        'Referer': 'https://www.kugou.com/',
                                        'Cookie': 'kg_mid=' + kgMid + '; kg_dfid=' + kgMid.substring(0, 24) + ';',
                                        'Accept': 'application/json, text/plain, */*',
                                        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                                        'x-requested-with': 'XMLHttpRequest'
                                    }
                                }, (followRes) => {
                                    let data2 = '';
                                    followRes.on('data', c => data2 += c);
                                    followRes.on('end', () => {
                                        try { return sendJson(res, JSON.parse(data2)); }
                                        catch (e2) {
                                            console.log(`[kugouWebApi] 重定向响应非JSON: ${data2.substring(0, 200)}`);
                                            return sendJson(res, { status: 0, error: 'follow redirect parse error', raw: data2.substring(0, 500) });
                                        }
                                    });
                                }).on('error', (e2) => {
                                    console.log(`[kugouWebApi] 重定向请求失败: ${e2.message}`);
                                    if (useHttps) { tryRequest(false); return; }
                                    sendJson(res, { status: 0, error: e2.message }, 500);
                                });
                                return;
                            }
                        }
                        let data = '';
                        apiRes.on('data', c => data += c);
                        apiRes.on('end', () => {
                            try { return sendJson(res, JSON.parse(data)); }
                            catch (e) {
                                // HTTPS 失败时尝试 HTTP 回退
                                if (useHttps) {
                                    console.log(`[kugouWebApi] HTTPS 返回非 JSON，尝试 HTTP 回退...`);
                                    tryRequest(false);
                                } else {
                                    return sendJson(res, { status: 0, error: 'parse error: ' + e.message, raw: data.substring(0, 500) });
                                }
                            }
                        });
                    }).on('error', (e) => {
                        if (useHttps) {
                            console.log(`[kugouWebApi] HTTPS 请求失败，尝试 HTTP 回退: ${e.message}`);
                            tryRequest(false);
                        } else {
                            sendJson(res, { status: 0, error: e.message }, 500);
                        }
                    });
                };

                // 先尝试 HTTPS
                tryRequest(true);
            } catch (e) { sendJson(res, { status: 0, error: e.message }, 500); }
            return;
        }

        sendJson(res, { error: "Not Found" }, 404);
    } catch (e) { console.error("[server] unhandled error:", e); sendJson(res, { error: e.message }, 500); }
});

server.listen(PORT, "127.0.0.1", () => console.log("Netease login server ready on port " + PORT));
