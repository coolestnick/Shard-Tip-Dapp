const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

// Security middleware
app.use(helmet());

// Configure CORS for production
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'];
    if (!origin || allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);

// Simple API key middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (process.env.API_KEY && apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: Invalid API key' });
  }
  next();
};

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const walletConnectionSchema = new mongoose.Schema({
  walletAddress: {
    type: String,
    required: true,
    lowercase: true
  },
  connectionTimestamp: {
    type: Date,
    default: Date.now
  },
  userAgent: String,
  ipAddress: String
});

const tipTransactionSchema = new mongoose.Schema({
  fromWallet: {
    type: String,
    required: true,
    lowercase: true
  },
  toWallet: {
    type: String,
    required: true,
    lowercase: true
  },
  amount: {
    type: String,
    required: true
  },
  amountInWei: {
    type: String,
    required: true
  },
  transactionHash: String,
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed'],
    default: 'pending'
  },
  sessionId: String
});

const WalletConnection = mongoose.model('WalletConnection', walletConnectionSchema);
const TipTransaction = mongoose.model('TipTransaction', tipTransactionSchema);

app.post('/api/wallet-connection', authenticateApiKey, async (req, res) => {
  try {
    const { walletAddress } = req.body;
    const userAgent = req.headers['user-agent'];
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    const connection = new WalletConnection({
      walletAddress,
      userAgent,
      ipAddress
    });
    
    await connection.save();
    res.status(201).json({ message: 'Wallet connection logged', id: connection._id });
  } catch (error) {
    console.error('Error logging wallet connection:', error);
    res.status(500).json({ error: 'Failed to log wallet connection' });
  }
});

app.post('/api/tip-transaction', authenticateApiKey, async (req, res) => {
  try {
    const { fromWallet, toWallet, amount, amountInWei, transactionHash, status, sessionId } = req.body;
    
    const transaction = new TipTransaction({
      fromWallet,
      toWallet,
      amount,
      amountInWei,
      transactionHash,
      status,
      sessionId
    });
    
    await transaction.save();
    res.status(201).json({ message: 'Transaction logged', id: transaction._id });
  } catch (error) {
    console.error('Error logging transaction:', error);
    res.status(500).json({ error: 'Failed to log transaction' });
  }
});

app.patch('/api/tip-transaction/:id', authenticateApiKey, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, transactionHash } = req.body;
    
    const transaction = await TipTransaction.findByIdAndUpdate(
      id,
      { status, transactionHash },
      { new: true }
    );
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json({ message: 'Transaction updated', transaction });
  } catch (error) {
    console.error('Error updating transaction:', error);
    res.status(500).json({ error: 'Failed to update transaction' });
  }
});

app.get('/api/wallet-connections/:walletAddress', async (req, res) => {
  try {
    const { walletAddress } = req.params;
    const connections = await WalletConnection.find({ 
      walletAddress: walletAddress.toLowerCase() 
    }).sort({ connectionTimestamp: -1 });
    
    res.json(connections);
  } catch (error) {
    console.error('Error fetching wallet connections:', error);
    res.status(500).json({ error: 'Failed to fetch wallet connections' });
  }
});

app.get('/api/tip-transactions/:walletAddress', async (req, res) => {
  try {
    const { walletAddress } = req.params;
    const { role } = req.query;
    
    let query = {};
    if (role === 'sender') {
      query.fromWallet = walletAddress.toLowerCase();
    } else if (role === 'receiver') {
      query.toWallet = walletAddress.toLowerCase();
    } else {
      query = {
        $or: [
          { fromWallet: walletAddress.toLowerCase() },
          { toWallet: walletAddress.toLowerCase() }
        ]
      };
    }
    
    const transactions = await TipTransaction.find(query).sort({ timestamp: -1 });
    res.json(transactions);
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Get all unique wallet addresses that have interacted with the dapp
app.get('/api/all-wallets', async (req, res) => {
  try {
    const connections = await WalletConnection.distinct('walletAddress');
    const transactions = await TipTransaction.find({}, 'fromWallet toWallet').lean();
    
    const allWallets = new Set(connections);
    transactions.forEach(tx => {
      allWallets.add(tx.fromWallet);
      allWallets.add(tx.toWallet);
    });
    
    const walletsArray = Array.from(allWallets).filter(wallet => wallet);
    
    res.json({
      totalWallets: walletsArray.length,
      wallets: walletsArray
    });
  } catch (error) {
    console.error('Error fetching all wallets:', error);
    res.status(500).json({ error: 'Failed to fetch wallets' });
  }
});

// Get detailed statistics about all interactions
app.get('/api/interaction-stats', async (req, res) => {
  try {
    const totalConnections = await WalletConnection.countDocuments();
    const uniqueConnectedWallets = await WalletConnection.distinct('walletAddress');
    const totalTransactions = await TipTransaction.countDocuments();
    const completedTransactions = await TipTransaction.countDocuments({ status: 'completed' });
    const failedTransactions = await TipTransaction.countDocuments({ status: 'failed' });
    const pendingTransactions = await TipTransaction.countDocuments({ status: 'pending' });
    
    // Get total volume
    const completedTxs = await TipTransaction.find({ status: 'completed' }, 'amount').lean();
    const totalVolume = completedTxs.reduce((sum, tx) => sum + parseFloat(tx.amount || 0), 0);
    
    // Get top creators by tips received
    const topCreators = await TipTransaction.aggregate([
      { $match: { status: 'completed' } },
      { $group: {
          _id: '$toWallet',
          totalReceived: { $sum: { $toDouble: '$amount' } },
          tipCount: { $sum: 1 }
        }
      },
      { $sort: { totalReceived: -1 } },
      { $limit: 10 }
    ]);
    
    // Get top tippers
    const topTippers = await TipTransaction.aggregate([
      { $match: { status: 'completed' } },
      { $group: {
          _id: '$fromWallet',
          totalSent: { $sum: { $toDouble: '$amount' } },
          tipCount: { $sum: 1 }
        }
      },
      { $sort: { totalSent: -1 } },
      { $limit: 10 }
    ]);
    
    res.json({
      connections: {
        total: totalConnections,
        uniqueWallets: uniqueConnectedWallets.length
      },
      transactions: {
        total: totalTransactions,
        completed: completedTransactions,
        failed: failedTransactions,
        pending: pendingTransactions,
        totalVolumeSHM: totalVolume.toFixed(4)
      },
      topCreators: topCreators.map(c => ({
        address: c._id,
        totalReceived: c.totalReceived.toFixed(4),
        tipCount: c.tipCount
      })),
      topTippers: topTippers.map(t => ({
        address: t._id,
        totalSent: t.totalSent.toFixed(4),
        tipCount: t.tipCount
      }))
    });
  } catch (error) {
    console.error('Error fetching interaction stats:', error);
    res.status(500).json({ error: 'Failed to fetch interaction statistics' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});