const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(express.json());

// Generate a hash for our test user password - "Password123"
const testPassword = "Password123";
// Using a synchronous hash for initialization
const hashedPassword = bcrypt.hashSync(testPassword, 10);
console.log('Generated hash for Password123:', hashedPassword);

// Mock database with updated password hash
const users = [
  {
    id: 1,
    email: 'admin@example.com',
    // Using synchronous hash for initialization
    password: bcrypt.hashSync("Password123", 10),
    name: 'Admin User',
    role: 'admin'
  },
  {
    id: 2,
    email: 'test@example.com',
    // Using the fresh hash we just generated
    password: hashedPassword,
    name: 'Test User',
    role: 'user'
  }
];

// Health endpoints
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'trackable-doors-api'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    version: 'v1',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/v1/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    version: 'v1',
    timestamp: new Date().toISOString()
  });
});

// Version endpoint
app.get('/version', (req, res) => {
  res.json({ 
    version: '1.0.0',
    api: 'trackable-doors-api'
  });
});

// Authentication endpoint
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    console.log('Login attempt:', { email: req.body.email, password: '******' });

    const { email, password } = req.body;

    if (!email || !password) {
      console.log('Missing credentials');
      return res.status(400).json({
        status: 'error',
        message: 'Email and password are required'
      });
    }

    const user = users.find(u => u.email === email);
    
    if (!user) {
      console.log('User not found');
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    // For debugging
    console.log('Found user:', { id: user.id, email: user.email });
    console.log('Comparing password with hash');

    const isValidPassword = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        role: user.role 
      },
      process.env.JWT_SECRET || 'your_jwt_secret_key_at_least_32_characters_long',
      { expiresIn: process.env.JWT_EXPIRES_IN || '90d' }
    );

    const { password: _, ...userWithoutPassword } = user;

    console.log('Login successful for user:', userWithoutPassword);
    res.json({
      status: 'success',
      token,
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// User profile endpoint
app.get('/api/v1/users/me', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({
      status: 'error',
      message: 'No authorization header'
    });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key_at_least_32_characters_long');
    
    const user = users.find(u => u.id === decoded.id);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(401).json({
      status: 'error',
      message: 'Invalid token'
    });
  }
});

// Doors endpoint
app.get('/api/v1/doors', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({
      status: 'error',
      message: 'No authorization header'
    });
  }

  try {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key_at_least_32_characters_long');
    
    // Return mock doors data
    res.json([
      {
        id: 1,
        name: 'Front Door',
        status: 'locked',
        lastAccessed: new Date().toISOString()
      },
      {
        id: 2,
        name: 'Back Door',
        status: 'unlocked',
        lastAccessed: new Date().toISOString()
      }
    ]);
  } catch (error) {
    res.status(401).json({
      status: 'error',
      message: 'Invalid token'
    });
  }
});

// Catch all route
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found',
    path: req.path
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`API is ready for testing at http://localhost:${port}`);
  console.log('You can test authentication with:');
  console.log('  Email: test@example.com');
  console.log('  Password: Password123');
});
