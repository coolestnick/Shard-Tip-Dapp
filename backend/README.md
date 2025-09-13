# Shardeum Tip DApp Backend

A robust Node.js backend API for the Shardeum Tip DApp, built with Express.js and MongoDB. This backend handles wallet connections, tip transactions, and provides analytics for the tipping platform.

## 🚀 Features

- **Wallet Management**: Track wallet connections and usage
- **Transaction Logging**: Record and monitor tip transactions
- **Usage Analytics**: Check if wallets have used the dApp
- **Rate Limiting**: Built-in protection against abuse
- **Error Handling**: Comprehensive error handling with auto-recovery
- **Input Validation**: Robust validation for wallet addresses and amounts
- **MongoDB Integration**: Optimized database operations with indexing
- **Vercel Ready**: Configured for serverless deployment

## 📚 API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check endpoint |
| `GET` | `/` | API documentation |

### Wallet Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/wallet-connection` | Log wallet connection |
| `GET` | `/api/wallet-usage/:walletAddress` | **Check if wallet has used dApp** |
| `GET` | `/api/wallet-connections/:walletAddress` | Get wallet connection history |

### Transaction Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/tip-transaction` | Log tip transaction |
| `PATCH` | `/api/tip-transaction/:id` | Update transaction status |
| `GET` | `/api/tip-transactions/:walletAddress` | Get wallet transactions |

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/all-wallets` | Get all wallet addresses |
| `GET` | `/api/interaction-stats` | Get platform statistics |

## 🔑 Key Feature: Wallet Usage Check

The `/api/wallet-usage/:walletAddress` endpoint returns whether a wallet has used the dApp:

```json
{
  "success": true,
  "data": {
    "walletAddress": "0x1234...5678",
    "hasUsedDapp": true,
    "hasConnected": true,
    "hasTransacted": false,
    "firstConnection": "2023-12-01T10:00:00.000Z",
    "lastActivity": "2023-12-01T10:00:00.000Z"
  }
}
```

## 🛠️ Installation & Setup

### Prerequisites

- Node.js >= 18.0.0
- MongoDB database
- npm or yarn

### Local Development

1. **Clone and navigate to backend directory**
   ```bash
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   MONGODB_URI=your-mongodb-connection-string
   PORT=3001
   ALLOWED_ORIGINS=http://localhost:3000,your-frontend-url
   API_KEY=your-secure-api-key
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Test the API**
   ```bash
   curl http://localhost:3001/health
   ```

## ☁️ Vercel Deployment

### Automatic Deployment

1. **Connect to Vercel**
   ```bash
   npm i -g vercel
   vercel login
   ```

2. **Deploy**
   ```bash
   vercel --prod
   ```

### Environment Variables

Set these in your Vercel dashboard:

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGODB_URI` | MongoDB connection string | `mongodb+srv://user:pass@cluster.mongodb.net/db` |
| `API_KEY` | API security key | `your-secure-api-key-here` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `https://your-frontend.vercel.app` |
| `NODE_ENV` | Environment | `production` |

### Manual Configuration

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Import your repository
3. Set Framework Preset to "Other"
4. Set Build and Output Settings:
   - Build Command: `npm run build`
   - Output Directory: Leave empty
   - Install Command: `npm install`
5. Add environment variables
6. Deploy

## 🔒 Security Features

- **Helmet**: Security headers
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **API Key Authentication**: Required for write operations
- **Input Validation**: Comprehensive validation for all inputs
- **CORS**: Configurable cross-origin resource sharing
- **Error Sanitization**: Clean error responses in production

## 📊 Error Handling

The backend includes comprehensive error handling:

- **Global Error Handler**: Catches all unhandled errors
- **Async Error Wrapper**: Handles promise rejections
- **Input Validation**: Returns detailed validation errors
- **MongoDB Error Handling**: Specific handling for database errors
- **Auto-Recovery**: Automatic reconnection for database disconnections

## Database Schema

### WalletConnection
- walletAddress: User's wallet address
- connectionTimestamp: When wallet was connected
- userAgent: Browser information
- ipAddress: User's IP address

### TipTransaction
- fromWallet: Sender's wallet address
- toWallet: Recipient's wallet address
- amount: Amount in SHM
- amountInWei: Amount in Wei
- transactionHash: Blockchain transaction hash
- timestamp: When transaction was initiated
- status: pending/completed/failed
- sessionId: Session identifier

## 🔧 Configuration

### Rate Limiting
```javascript
// Current settings: 100 requests per 15 minutes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
```

### CORS
```javascript
// Configure allowed origins in environment variable
ALLOWED_ORIGINS=http://localhost:3000,https://your-domain.com
```

### MongoDB Connection
```javascript
// Auto-retry and connection pooling configured
const mongoOptions = {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
};
```

## 🧪 Testing

```bash
# Health check
curl https://your-api-domain.vercel.app/health

# Check wallet usage
curl https://your-api-domain.vercel.app/api/wallet-usage/0x1234567890123456789012345678901234567890

# Get platform stats
curl https://your-api-domain.vercel.app/api/interaction-stats
```

## 📈 Monitoring

Monitor your deployment:

1. **Vercel Analytics**: Built-in request monitoring
2. **Health Endpoint**: `/health` for uptime monitoring
3. **Error Logging**: Comprehensive error logging
4. **MongoDB Monitoring**: Connection status tracking

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License.

---

**Ready for production deployment on Vercel with automatic scaling and error recovery!**