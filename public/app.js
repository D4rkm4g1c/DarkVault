// Global variables
let currentUser = null;
const API_URL = 'http://localhost:3000/api';

// DOM Elements
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginTab = document.getElementById('login-tab');
const registerTab = document.getElementById('register-tab');
const authSection = document.getElementById('auth-section');
const appSection = document.getElementById('app-section');
const logoutBtn = document.getElementById('btn-logout');
const navHome = document.getElementById('nav-home');
const navTransfer = document.getElementById('nav-transfer');
const navTransactions = document.getElementById('nav-transactions');
const navProfile = document.getElementById('nav-profile');
const navAdmin = document.getElementById('nav-admin');
const adminSection = document.getElementById('admin-section');
const homeSection = document.getElementById('home-section');
const transferSection = document.getElementById('transfer-section');
const transactionsSection = document.getElementById('transactions-section');
const profileSection = document.getElementById('profile-section');
const adminSectionContent = document.getElementById('admin-section-content');
const transferForm = document.getElementById('transfer-form');
const messageForm = document.getElementById('message-form');
const messageUserId = document.getElementById('message-user-id');
const userBalance = document.getElementById('user-balance');
const quickTransfer = document.getElementById('quick-transfer');
const quickSearch = document.getElementById('quick-search');
const btnUpload = document.getElementById('btn-upload');
const uploadModal = new bootstrap.Modal(document.getElementById('uploadModal'));
const searchModal = new bootstrap.Modal(document.getElementById('searchModal'));
const btnSearch = document.getElementById('btn-search');
const searchTerm = document.getElementById('search-term');
const searchResults = document.getElementById('search-results');
const btnUploadSubmit = document.getElementById('btn-upload-submit');
const uploadFile = document.getElementById('upload-file');
const btnExportUsers = document.getElementById('btn-export-users');
const btnResetBalances = document.getElementById('btn-reset-balances');
const btnRunReport = document.getElementById('btn-run-report');
const reportName = document.getElementById('report-name');
const messageBanner = document.getElementById('message-banner');

// Check if there's a message in URL (vulnerable to XSS)
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  
  if (message) {
    messageBanner.style.display = 'block';
    // Vulnerable to XSS - directly injecting parameter into innerHTML
    messageBanner.innerHTML = message;
  }
  
  // Check for existing token
  const token = localStorage.getItem('token');
  if (token) {
    fetchUserData(token);
  }
});

// Tab switching
loginTab.addEventListener('click', (e) => {
  e.preventDefault();
  loginTab.classList.add('active');
  registerTab.classList.remove('active');
  loginForm.style.display = 'block';
  registerForm.style.display = 'none';
});

registerTab.addEventListener('click', (e) => {
  e.preventDefault();
  registerTab.classList.add('active');
  loginTab.classList.remove('active');
  registerForm.style.display = 'block';
  loginForm.style.display = 'none';
});

// Login form submission
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  
  try {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password }),
      credentials: 'include'
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Store token insecurely in localStorage
      localStorage.setItem('token', data.token);
      currentUser = data.user;
      showLoggedInState();
    } else {
      alert(data.message);
    }
  } catch (error) {
    console.error('Login error:', error);
    alert('An error occurred during login');
  }
});

// Register form submission
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('register-username').value;
  const password = document.getElementById('register-password').value;
  const email = document.getElementById('register-email').value;
  
  try {
    const response = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password, email })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert('Registration successful! Please login.');
      loginTab.click();
    } else {
      // Show detailed error message
      console.error('Registration error:', data);
      alert(`Registration error: ${data.error || 'Unknown error'}`);
    }
  } catch (error) {
    console.error('Register error:', error);
    alert(`Error during registration: ${error.message}`);
  }
});

// Fetch user data using token
async function fetchUserData(token) {
  try {
    const response = await fetch(`${API_URL}/users/1`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const userData = await response.json();
      currentUser = userData;
      showLoggedInState();
    } else {
      localStorage.removeItem('token');
    }
  } catch (error) {
    console.error('Error fetching user data:', error);
    localStorage.removeItem('token');
  }
}

// Show logged in state
function showLoggedInState() {
  authSection.style.display = 'none';
  appSection.style.display = 'block';
  logoutBtn.style.display = 'block';
  
  // Update user info display
  document.getElementById('summary-username').textContent = currentUser.username;
  document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
  document.getElementById('summary-role').textContent = currentUser.role;
  userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
  
  // Update profile section
  document.getElementById('profile-id').textContent = currentUser.id;
  document.getElementById('profile-username').textContent = currentUser.username;
  document.getElementById('profile-email').textContent = currentUser.email;
  document.getElementById('profile-role').textContent = currentUser.role;
  
  // Set user ID for messaging (vulnerable to parameter tampering)
  messageUserId.value = currentUser.id;
  
  // Show admin section if admin
  if (currentUser.role === 'admin') {
    adminSection.style.display = 'block';
  }
  
  // Show home section by default
  showSection(homeSection);
  
  // Load transactions
  loadTransactions();
}

// Navigation
navHome.addEventListener('click', () => showSection(homeSection));
navTransfer.addEventListener('click', () => showSection(transferSection));
navTransactions.addEventListener('click', () => {
  loadTransactions();
  showSection(transactionsSection);
});
navProfile.addEventListener('click', () => showSection(profileSection));
navAdmin.addEventListener('click', () => {
  loadAdminMessages();
  showSection(adminSectionContent);
});

// Quick actions
quickTransfer.addEventListener('click', () => showSection(transferSection));
quickSearch.addEventListener('click', () => searchModal.show());
btnUpload.addEventListener('click', () => uploadModal.show());

// Show section helper
function showSection(section) {
  const sections = document.querySelectorAll('.app-page');
  sections.forEach(s => s.style.display = 'none');
  section.style.display = 'block';
}

// Logout
logoutBtn.addEventListener('click', () => {
  localStorage.removeItem('token');
  currentUser = null;
  authSection.style.display = 'block';
  appSection.style.display = 'none';
  logoutBtn.style.display = 'none';
  adminSection.style.display = 'none';
});

// Transfer money
transferForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const to = document.getElementById('transfer-to').value;
  const amount = document.getElementById('transfer-amount').value;
  const note = document.getElementById('transfer-note').value;
  
  try {
    const token = localStorage.getItem('token');
    
    const response = await fetch(`${API_URL}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify({ to, amount, note })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert('Transfer successful!');
      transferForm.reset();
      
      // Update user balance (client-side only, vulnerable to manipulation)
      currentUser.balance -= parseFloat(amount);
      userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
      document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
      
      // Load updated transactions
      loadTransactions();
    } else {
      alert(data.error || 'Transfer failed');
    }
  } catch (error) {
    console.error('Transfer error:', error);
    alert('An error occurred during transfer');
  }
});

// Load transactions
async function loadTransactions() {
  if (!currentUser) return;
  
  try {
    const token = localStorage.getItem('token');
    
    // Directly fetch from the database without proper validation
    const response = await fetch(`${API_URL}/users/${currentUser.id}`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      // Get updated user data
      const userData = await response.json();
      currentUser.balance = userData.balance;
      userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
      document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
      
      // Now fetch transactions
      const txResponse = await fetch(`${API_URL}/transactions?user_id=${currentUser.id}`, {
        headers: {
          'Authorization': token
        }
      });
      
      if (txResponse.ok) {
        const transactions = await txResponse.json();
        displayTransactions(transactions);
      }
    }
  } catch (error) {
    console.error('Error loading transactions:', error);
  }
}

// Display transactions in the table
function displayTransactions(transactions) {
  const tableBody = document.getElementById('transactions-table');
  tableBody.innerHTML = '';
  
  if (transactions.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No transactions found</td></tr>';
    return;
  }
  
  transactions.forEach(tx => {
    const row = document.createElement('tr');
    
    // Add class based on transaction type
    if (tx.sender_id === currentUser.id) {
      row.classList.add('transaction-sent');
    } else {
      row.classList.add('transaction-received');
    }
    
    // Vulnerable to XSS via transaction note
    row.innerHTML = `
      <td>${tx.id}</td>
      <td>${tx.sender_id === currentUser.id ? 'Sent' : 'Received'}</td>
      <td>$${parseFloat(tx.amount).toFixed(2)}</td>
      <td>${tx.sender_id === currentUser.id ? 'To: ' + tx.receiver_id : 'From: ' + tx.sender_id}</td>
      <td>${new Date(tx.date).toLocaleString()}</td>
      <td>${tx.note}</td>
    `;
    
    tableBody.appendChild(row);
  });
}

// Send message to admin
messageForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const message = document.getElementById('message-text').value;
  
  // Vulnerable to parameter tampering - using client-side user ID
  const user_id = messageUserId.value;
  
  try {
    const token = localStorage.getItem('token');
    
    const response = await fetch(`${API_URL}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify({ user_id, message })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert('Message sent to admin!');
      messageForm.reset();
    } else {
      alert(data.error || 'Failed to send message');
    }
  } catch (error) {
    console.error('Message error:', error);
    alert('An error occurred while sending message');
  }
});

// Search for users
btnSearch.addEventListener('click', async () => {
  const term = searchTerm.value;
  
  if (!term) {
    searchResults.innerHTML = '<p>Please enter a search term</p>';
    return;
  }
  
  try {
    const token = localStorage.getItem('token');
    
    const response = await fetch(`${API_URL}/search?term=${term}`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const users = await response.json();
      
      if (users.length === 0) {
        searchResults.innerHTML = '<p>No users found</p>';
        return;
      }
      
      searchResults.innerHTML = '';
      
      users.forEach(user => {
        const div = document.createElement('div');
        div.className = 'user-result';
        
        // Vulnerable to XSS if term is reflected in results
        div.innerHTML = `
          <p><strong>ID:</strong> ${user.id}</p>
          <p><strong>Username:</strong> ${user.username}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <button class="btn btn-sm btn-primary btn-transfer-to" data-user-id="${user.id}">Transfer to this user</button>
        `;
        
        searchResults.appendChild(div);
      });
      
      // Add event listeners to transfer buttons
      document.querySelectorAll('.btn-transfer-to').forEach(btn => {
        btn.addEventListener('click', function() {
          const userId = this.getAttribute('data-user-id');
          searchModal.hide();
          showSection(transferSection);
          document.getElementById('transfer-to').value = userId;
        });
      });
    } else {
      const data = await response.json();
      searchResults.innerHTML = `<p>Error: ${data.error || 'Search failed'}</p>`;
    }
  } catch (error) {
    console.error('Search error:', error);
    searchResults.innerHTML = '<p>An error occurred during search</p>';
  }
});

// Upload file
btnUploadSubmit.addEventListener('click', async () => {
  const file = uploadFile.files[0];
  
  if (!file) {
    alert('Please select a file');
    return;
  }
  
  const formData = new FormData();
  formData.append('file', file);
  
  try {
    const token = localStorage.getItem('token');
    
    const response = await fetch(`${API_URL}/upload`, {
      method: 'POST',
      headers: {
        'Authorization': token
      },
      body: formData
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert(`File uploaded successfully! Path: ${data.file_path}`);
      uploadModal.hide();
      uploadFile.value = '';
    } else {
      alert(data.message || 'Upload failed');
    }
  } catch (error) {
    console.error('Upload error:', error);
    alert('An error occurred during upload');
  }
});

// Admin features
if (btnExportUsers) {
  btnExportUsers.addEventListener('click', async () => {
    try {
      const token = localStorage.getItem('token');
      
      // Vulnerable to parameter tampering - URL parameter can be modified
      const response = await fetch(`${API_URL}/admin/export-users?isAdmin=true`, {
        headers: {
          'Authorization': token
        }
      });
      
      if (response.ok) {
        const users = await response.json();
        console.log('Exported users:', users);
        
        // Create CSV
        let csv = 'ID,Username,Email,Password,Role,Balance\n';
        users.forEach(user => {
          csv += `${user.id},"${user.username}","${user.email}","${user.password}","${user.role}",${user.balance}\n`;
        });
        
        // Download file
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'users.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      } else {
        alert('Failed to export users');
      }
    } catch (error) {
      console.error('Export error:', error);
      alert('An error occurred during export');
    }
  });
}

if (btnRunReport) {
  btnRunReport.addEventListener('click', async () => {
    const report = reportName.value;
    
    if (!report) {
      alert('Please enter a report name');
      return;
    }
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await fetch(`${API_URL}/admin/run-report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify({ report_name: report })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert(`Report generated successfully!\nOutput: ${data.output}`);
      } else {
        alert(data.error || 'Failed to generate report');
      }
    } catch (error) {
      console.error('Report error:', error);
      alert('An error occurred while generating report');
    }
  });
}

// Load admin messages
async function loadAdminMessages() {
  if (!currentUser || currentUser.role !== 'admin') return;
  
  try {
    const token = localStorage.getItem('token');
    
    const response = await fetch(`${API_URL}/admin/messages`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const messages = await response.json();
      displayAdminMessages(messages);
    }
  } catch (error) {
    console.error('Error loading admin messages:', error);
  }
}

// Display admin messages
function displayAdminMessages(messages) {
  const messagesDiv = document.getElementById('admin-messages');
  messagesDiv.innerHTML = '';
  
  if (!messages || messages.length === 0) {
    messagesDiv.innerHTML = '<p class="text-center">No messages</p>';
    return;
  }
  
  messages.forEach(msg => {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'admin-message';
    
    // Vulnerable to XSS via message content
    messageDiv.innerHTML = `
      <div class="admin-message-meta">
        From: ${msg.username || 'Unknown'} (ID: ${msg.user_id}) - ${new Date(msg.date).toLocaleString()}
      </div>
      <p class="admin-message-content">${msg.message}</p>
    `;
    
    messagesDiv.appendChild(messageDiv);
  });
} 