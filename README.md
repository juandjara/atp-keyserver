## atp-keyserver
private key storage for ATProto

### Requirements
- [Bun](https://bun.sh/) v1.0 or higher

### Installation
```bash
bun install
```

### Development
```bash
bun run dev
```

### Production
```bash
DID=your-service-did bun start
```

### Environment Variables
- `DID` (required): The DID of the deployed service
- `PORT` (optional): Server port (defaults to 3000)

### Database
This server uses Bun's built-in SQLite for persistent key storage. The database file (`keyserver.db`) will be created automatically on first run.
