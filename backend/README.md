# Shardeum Tip DApp Backend

## Setup

1. Install dependencies:
```bash
cd backend
npm install
```

2. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

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

## API Endpoints

- POST /api/wallet-connection - Log wallet connection
- POST /api/tip-transaction - Create transaction record
- PATCH /api/tip-transaction/:id - Update transaction status
- GET /api/wallet-connections/:walletAddress - Get wallet connection history
- GET /api/tip-transactions/:walletAddress - Get transaction history