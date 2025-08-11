// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// 中间件
app.use(express.json());

// -------------------- 数据库连接 --------------------
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('MongoDB 连接成功');
}).catch(err => {
    console.error('MongoDB 连接失败', err);
});

// -------------------- 数据库 Schema --------------------
const keySchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
    name: String,
    category: String,
    status: { type: String, default: '在库' },
    department: String,
    location: String,
    holder: String,
    borrowDate: Date,
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['总管理员', '普通用户'], default: '普通用户' }
});

const Key = mongoose.model('Key', keySchema);
const User = mongoose.model('User', userSchema);

// -------------------- 路由（API 接口） --------------------

// 注册用户 (仅供测试，生产环境不应公开此接口)
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = new User({ username, passwordHash, role });
        await newUser.save();
        res.status(201).json({ message: '用户注册成功' });
    } catch (err) {
        res.status(500).json({ message: '用户注册失败', error: err.message });
    }
});

// 登录
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: '用户名或密码错误' });
    }

    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: '登录成功', token, user: { username: user.username, role: user.role } });
});

// JWT 验证中间件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 获取所有钥匙 (需要身份验证)
app.get('/api/keys', authenticateToken, async (req, res) => {
    try {
        const keys = await Key.find();
        res.json(keys);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// 添加钥匙 (需要身份验证)
app.post('/api/keys', authenticateToken, async (req, res) => {
    const key = new Key(req.body);
    try {
        const newKey = await key.save();
        res.status(201).json(newKey);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器正在 port ${PORT} 上运行`);
});