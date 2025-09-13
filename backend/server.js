const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

// Import built-in modules for better error handling
const { promisify } = require('util');

const app = express();

// Global error handler
const globalErrorHandler = (err, req, res, next) => {
  console.error('Global error handler:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });

  // Mongoose validation errors
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      details: errors
    });
  }

  // Mongoose cast errors (invalid ObjectId)
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      error: 'Invalid ID format'
    });
  }

  // MongoDB duplicate key errors
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({
      success: false,
      error: `Duplicate ${field} value`
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: 'Invalid token'
    });
  }

  // Default error
  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Async error wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Input validation helpers
const validateWalletAddress = (address) => {
  if (!address || typeof address !== 'string') {
    throw new Error('Wallet address is required and must be a string');
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    throw new Error('Invalid wallet address format');
  }
  return address.toLowerCase();
};

const validateAmount = (amount) => {
  if (!amount || typeof amount !== 'string') {
    throw new Error('Amount is required and must be a string');
  }
  const numAmount = parseFloat(amount);
  if (isNaN(numAmount) || numAmount <= 0) {
    throw new Error('Amount must be a positive number');
  }
  return amount;
};

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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);

// Simple API key middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (process.env.API_KEY && apiKey !== process.env.API_KEY) {
    return res.status(401).json({ 
      success: false,
      error: 'Unauthorized: Invalid API key' 
    });
  }
  next();
};

// Enhanced MongoDB connection with better error handling and auto-retry
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      bufferCommands: false,
      bufferMaxEntries: 0,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection error:', error);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

connectDB();

// Handle MongoDB connection events
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  setTimeout(connectDB, 5000);
});

mongoose.connection.on('reconnected', () => {
  console.log('MongoDB reconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Received SIGINT. Graceful shutdown...');
  await mongoose.connection.close();
  console.log('MongoDB connection closed due to app termination');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Received SIGTERM. Graceful shutdown...');
  await mongoose.connection.close();
  console.log('MongoDB connection closed due to app termination');
  process.exit(0);
});

// Schemas
const walletConnectionSchema = new mongoose.Schema({
  walletAddress: {
    type: String,
    required: [true, 'Wallet address is required'],
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^0x[a-fA-F0-9]{40}$/.test(v);
      },
      message: 'Invalid wallet address format'
    }
  },
  connectionTimestamp: {
    type: Date,
    default: Date.now
  },
  userAgent: String,
  ipAddress: String
}, {
  timestamps: true
});

const tipTransactionSchema = new mongoose.Schema({
  fromWallet: {
    type: String,
    required: [true, 'From wallet address is required'],
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^0x[a-fA-F0-9]{40}$/.test(v);
      },
      message: 'Invalid from wallet address format'
    }
  },
  toWallet: {
    type: String,
    required: [true, 'To wallet address is required'],
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^0x[a-fA-F0-9]{40}$/.test(v);
      },
      message: 'Invalid to wallet address format'
    }
  },
  amount: {
    type: String,
    required: [true, 'Amount is required'],
    validate: {
      validator: function(v) {
        const num = parseFloat(v);
        return !isNaN(num) && num > 0;
      },
      message: 'Amount must be a positive number'
    }
  },
  amountInWei: {
    type: String,
    required: [true, 'Amount in Wei is required']
  },
  transactionHash: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || /^0x[a-fA-F0-9]{64}$/.test(v);
      },
      message: 'Invalid transaction hash format'
    }
  },
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
}, {
  timestamps: true
});

// Add indexes for better performance
walletConnectionSchema.index({ walletAddress: 1 });
walletConnectionSchema.index({ connectionTimestamp: -1 });

tipTransactionSchema.index({ fromWallet: 1 });
tipTransactionSchema.index({ toWallet: 1 });
tipTransactionSchema.index({ status: 1 });
tipTransactionSchema.index({ timestamp: -1 });
tipTransactionSchema.index({ transactionHash: 1 });

const WalletConnection = mongoose.model('WalletConnection', walletConnectionSchema);
const TipTransaction = mongoose.model('TipTransaction', tipTransactionSchema);

// API Routes

// Log wallet connection
app.post('/api/wallet-connection', authenticateApiKey, asyncHandler(async (req, res) => {
  const { walletAddress } = req.body;
  
  if (!walletAddress) {
    return res.status(400).json({
      success: false,
      error: 'Wallet address is required'
    });
  }

  const validatedAddress = validateWalletAddress(walletAddress);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const ipAddress = req.headers['x-forwarded-for'] || 
                   req.headers['x-real-ip'] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress ||
                   (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
                   'Unknown';
  
  const connection = new WalletConnection({
    walletAddress: validatedAddress,
    userAgent,
    ipAddress
  });
  
  await connection.save();
  
  res.status(201).json({ 
    success: true,
    message: 'Wallet connection logged successfully', 
    data: {
      id: connection._id,
      walletAddress: validatedAddress,
      timestamp: connection.connectionTimestamp
    }
  });
}));

// Log tip transaction
app.post('/api/tip-transaction', authenticateApiKey, asyncHandler(async (req, res) => {
  const { fromWallet, toWallet, amount, amountInWei, transactionHash, status, sessionId } = req.body;
  
  // Validate required fields
  if (!fromWallet || !toWallet || !amount || !amountInWei) {
    return res.status(400).json({
      success: false,
      error: 'fromWallet, toWallet, amount, and amountInWei are required'
    });
  }

  // Validate wallet addresses
  const validatedFromWallet = validateWalletAddress(fromWallet);
  const validatedToWallet = validateWalletAddress(toWallet);
  
  // Validate amount
  const validatedAmount = validateAmount(amount);
  
  // Validate status if provided
  const validStatuses = ['pending', 'completed', 'failed'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: `Status must be one of: ${validStatuses.join(', ')}`
    });
  }

  // Validate transaction hash if provided
  if (transactionHash && !/^0x[a-fA-F0-9]{64}$/.test(transactionHash)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid transaction hash format'
    });
  }
  
  const transaction = new TipTransaction({
    fromWallet: validatedFromWallet,
    toWallet: validatedToWallet,
    amount: validatedAmount,
    amountInWei,
    transactionHash,
    status: status || 'pending',
    sessionId
  });
  
  await transaction.save();
  
  res.status(201).json({ 
    success: true,
    message: 'Transaction logged successfully', 
    data: {
      id: transaction._id,
      fromWallet: validatedFromWallet,
      toWallet: validatedToWallet,
      amount: validatedAmount,
      status: transaction.status,
      timestamp: transaction.timestamp
    }
  });
}));

// Update transaction status
app.patch('/api/tip-transaction/:id', authenticateApiKey, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status, transactionHash } = req.body;
  
  // Validate ObjectId format
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid transaction ID format'
    });
  }

  // Validate status if provided
  const validStatuses = ['pending', 'completed', 'failed'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: `Status must be one of: ${validStatuses.join(', ')}`
    });
  }

  // Validate transaction hash if provided
  if (transactionHash && !/^0x[a-fA-F0-9]{64}$/.test(transactionHash)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid transaction hash format'
    });
  }
  
  const updateData = {};
  if (status) updateData.status = status;
  if (transactionHash) updateData.transactionHash = transactionHash;
  
  if (Object.keys(updateData).length === 0) {
    return res.status(400).json({
      success: false,
      error: 'At least one field (status or transactionHash) must be provided'
    });
  }
  
  const transaction = await TipTransaction.findByIdAndUpdate(
    id,
    updateData,
    { new: true, runValidators: true }
  );
  
  if (!transaction) {
    return res.status(404).json({ 
      success: false,
      error: 'Transaction not found' 
    });
  }
  
  res.json({ 
    success: true,
    message: 'Transaction updated successfully', 
    data: transaction 
  });
}));

// Check if wallet has used the dapp (NEW API)
app.get('/api/wallet-usage/:walletAddress', asyncHandler(async (req, res) => {
  const { walletAddress } = req.params;
  
  if (!walletAddress) {
    return res.status(400).json({
      success: false,
      error: 'Wallet address is required'
    });
  }

  const validatedAddress = validateWalletAddress(walletAddress);
  
  // Check if wallet has connected
  const hasConnected = await WalletConnection.findOne({ 
    walletAddress: validatedAddress 
  });
  
  // Check if wallet has made any transactions
  const hasTransacted = await TipTransaction.findOne({
    $or: [
      { fromWallet: validatedAddress },
      { toWallet: validatedAddress }
    ]
  });
  
  const hasUsedDapp = !!(hasConnected || hasTransacted);
  
  res.json({
    success: true,
    data: {
      walletAddress: validatedAddress,
      hasUsedDapp,
      hasConnected: !!hasConnected,
      hasTransacted: !!hasTransacted,
      firstConnection: hasConnected?.connectionTimestamp || null,
      lastActivity: hasTransacted?.timestamp || hasConnected?.connectionTimestamp || null
    }
  });
}));

// Get wallet connections
app.get('/api/wallet-connections/:walletAddress', asyncHandler(async (req, res) => {
  const { walletAddress } = req.params;
  
  const validatedAddress = validateWalletAddress(walletAddress);
  
  const connections = await WalletConnection.find({ 
    walletAddress: validatedAddress 
  }).sort({ connectionTimestamp: -1 });
  
  res.json({
    success: true,
    data: {
      walletAddress: validatedAddress,
      connections,
      totalConnections: connections.length
    }
  });
}));

// Get wallet transactions
app.get('/api/tip-transactions/:walletAddress', asyncHandler(async (req, res) => {
  const { walletAddress } = req.params;
  const { role, status, limit = 50, offset = 0 } = req.query;
  
  const validatedAddress = validateWalletAddress(walletAddress);
  
  // Validate role if provided
  const validRoles = ['sender', 'receiver'];
  if (role && !validRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      error: `Role must be one of: ${validRoles.join(', ')}`
    });
  }

  // Validate status if provided
  const validStatuses = ['pending', 'completed', 'failed'];
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: `Status must be one of: ${validStatuses.join(', ')}`
    });
  }

  // Validate pagination parameters
  const limitNum = Math.min(parseInt(limit) || 50, 100); // Max 100 per request
  const offsetNum = Math.max(parseInt(offset) || 0, 0);
  
  let query = {};
  if (role === 'sender') {
    query.fromWallet = validatedAddress;
  } else if (role === 'receiver') {
    query.toWallet = validatedAddress;
  } else {
    query = {
      $or: [
        { fromWallet: validatedAddress },
        { toWallet: validatedAddress }
      ]
    };
  }
  
  // Add status filter if provided
  if (status) {
    query.status = status;
  }
  
  const [transactions, totalCount] = await Promise.all([
    TipTransaction.find(query)
      .sort({ timestamp: -1 })
      .limit(limitNum)
      .skip(offsetNum),
    TipTransaction.countDocuments(query)
  ]);
  
  res.json({
    success: true,
    data: {
      walletAddress: validatedAddress,
      transactions,
      pagination: {
        total: totalCount,
        limit: limitNum,
        offset: offsetNum,
        hasMore: offsetNum + limitNum < totalCount
      }
    }
  });
}));

// Get all unique wallet addresses that have interacted with the dapp
app.get('/api/all-wallets', asyncHandler(async (req, res) => {
  const { limit = 100, offset = 0 } = req.query;
  
  // Validate pagination parameters
  const limitNum = Math.min(parseInt(limit) || 100, 500); // Max 500 per request
  const offsetNum = Math.max(parseInt(offset) || 0, 0);
  
  const [connections, fromWallets, toWallets] = await Promise.all([
    WalletConnection.distinct('walletAddress'),
    TipTransaction.distinct('fromWallet'),
    TipTransaction.distinct('toWallet')
  ]);
  
  const allWalletsSet = new Set([...connections, ...fromWallets, ...toWallets]);
  const allWalletsArray = Array.from(allWalletsSet).filter(wallet => wallet);
  
  // Apply pagination
  const paginatedWallets = allWalletsArray.slice(offsetNum, offsetNum + limitNum);
  
  res.json({
    success: true,
    data: {
      wallets: paginatedWallets,
      pagination: {
        total: allWalletsArray.length,
        limit: limitNum,
        offset: offsetNum,
        hasMore: offsetNum + limitNum < allWalletsArray.length
      }
    }
  });
}));

// Get detailed statistics about all interactions
app.get('/api/interaction-stats', asyncHandler(async (req, res) => {
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
      success: true,
      data: {
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
      }
    });
  } catch (error) {
    console.error('Error fetching interaction stats:', error);
    res.status(500).json({ error: 'Failed to fetch interaction statistics' });
  }
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Debug endpoint for MongoDB connection troubleshooting
app.get('/debug', (req, res) => {
  res.json({
    success: true,
    debug: {
      mongodbUri: process.env.MONGODB_URI ? 'SET' : 'NOT SET',
      mongodbUriPreview: process.env.MONGODB_URI ? process.env.MONGODB_URI.substring(0, 50) + '...' : 'NOT SET',
      allowedOrigins: process.env.ALLOWED_ORIGINS || 'NOT SET',
      apiKey: process.env.API_KEY ? 'SET' : 'NOT SET',
      nodeEnv: process.env.NODE_ENV || 'NOT SET',
      mongooseReadyState: mongoose.connection.readyState,
      mongooseStates: {
        '0': 'disconnected',
        '1': 'connected',
        '2': 'connecting',
        '3': 'disconnecting'
      },
      currentState: {
        '0': 'disconnected',
        '1': 'connected',
        '2': 'connecting',
        '3': 'disconnecting'
      }[mongoose.connection.readyState] || 'unknown'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Shardeum Tip DApp Backend API',
    version: '1.0.0',
    endpoints: {
      'POST /api/wallet-connection': 'Log wallet connection',
      'POST /api/tip-transaction': 'Log tip transaction',
      'PATCH /api/tip-transaction/:id': 'Update transaction status',
      'GET /api/wallet-usage/:walletAddress': 'Check if wallet has used dapp',
      'GET /api/wallet-connections/:walletAddress': 'Get wallet connections',
      'GET /api/tip-transactions/:walletAddress': 'Get wallet transactions',
      'GET /api/all-wallets': 'Get all wallet addresses',
      'GET /api/interaction-stats': 'Get interaction statistics',
      'GET /health': 'Health check'
    }
  });
});

// Handle 404 errors
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.originalUrl} not found`
  });
});

// Apply global error handler
app.use(globalErrorHandler);

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.log('Unhandled Promise Rejection:', err.message);
  console.log('Shutting down the server due to unhandled promise rejection');
  // Don't exit in production, just log the error
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.log('Uncaught Exception:', err.message);
  console.log('Shutting down the server due to uncaught exception');
  // Don't exit in production, just log the error
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

const PORT = process.env.PORT || 3001;

// For Vercel deployment, export the app
if (process.env.VERCEL || process.env.NODE_ENV === 'production') {
  module.exports = app;
} else {
  // For local development
  const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
      console.log('Process terminated');
    });
  });
}