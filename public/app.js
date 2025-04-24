// Global variables
let currentUser = null;
// Use current domain for API instead of hardcoded localhost
const API_URL = `${window.location.protocol}//${window.location.host}/api`;

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
const transferForm = document.getElementById('transfer-form');
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
const btnRunReport = document.getElementById('btn-run-report');
const reportName = document.getElementById('report-name');
const messageBanner = document.getElementById('message-banner');
const feedbackForm = document.getElementById('feedback-form');
const adminMessageForm = document.getElementById('admin-message-form');
const btnSecuritySave = document.getElementById('btn-security-save');
const twoFactorToggle = document.getElementById('twoFactorToggle');
const recoveryEmail = document.getElementById('recovery-email');
const currentUserId = document.getElementById('current-user-id');
const userId = document.getElementById('user-id');

// Dashboard Stats Elements
const dashboardBalance = document.getElementById('dashboard-balance');
const totalReceived = document.getElementById('total-received');
const totalSent = document.getElementById('total-sent');
const accountStatus = document.getElementById('account-status');

// Exploit chain elements
const exploitProgress = document.getElementById('exploit-progress');
const exploitStage = document.getElementById('exploit-stage');
const exploitHint = document.getElementById('exploit-hint');
const btnCheckProgress = document.getElementById('btn-check-progress');

// Check if there's a message in URL
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  
  if (message) {
    messageBanner.style.display = 'block';
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
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      handleLoginSuccess(data);
    } else {
      alert(data.message || 'Login failed. Please check your credentials.');
    }
  } catch (error) {
    console.error('Login error:', error);
    // Only show error alert if we have a genuine network/parsing error
    // and authentication hasn't already succeeded
    if (!localStorage.getItem('token')) {
      alert('An error occurred during login. Please try again.');
    }
  }
});

// Register form submission
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('register-username').value;
  const password = document.getElementById('register-password').value;
  const email = document.getElementById('register-email').value;
  
  try {
    console.log('Attempting to register with:', { username, email });
    console.log('API URL:', API_URL);
    
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
    console.error('Register error details:', error);
    alert(`Error during registration: ${error.message}. Check console for details.`);
  }
});

// Fetch user data using token
async function fetchUserData(token) {
  try {
    // Decode the JWT token to get the user ID
    const tokenData = JSON.parse(atob(token.split('.')[1]));
    const userId = tokenData.id;
    
    // Always get fresh user data when this function is called
    const response = await fetch(`${API_URL}/users/${userId}`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const userData = await response.json();
      currentUser = userData;
      showLoggedInState();
      
      // Initialize dashboard stats
      updateDashboardStats();
      
      // If this is a bot token with secrets, show an alert
      if (userData.secretInfo) {
        const secretAlert = document.createElement('div');
        secretAlert.className = 'alert alert-warning alert-dismissible fade show fixed-top w-75 mx-auto mt-2';
        secretAlert.innerHTML = `
          <strong>Bot Token Detected!</strong> You are now logged in with ${userData.botType || 'an admin'} bot privileges. 
          Secret information is available in your profile.
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        document.body.appendChild(secretAlert);
        
        // Show profile section with the secrets
        showSection(profileSection);
      }
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
  
  // Set user information in balance display and summary card
  if (currentUser) {
    userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
    document.getElementById('summary-username').textContent = currentUser.username;
    document.getElementById('summary-role').textContent = currentUser.role;
    document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
    
    // Also update the home section data
    document.getElementById('home-username').textContent = currentUser.username;
    document.getElementById('home-balance').textContent = currentUser.balance.toFixed(2);
    document.getElementById('home-role').textContent = currentUser.role;
    
    // Set profile data
    document.getElementById('profile-id').textContent = currentUser.id;
    document.getElementById('profile-username').textContent = currentUser.username;
    document.getElementById('profile-email').textContent = currentUser.email;
    document.getElementById('profile-role').textContent = currentUser.role;
    
    // Set hidden user ID fields
    if (userId) userId.value = currentUser.id;
    if (currentUserId) currentUserId.value = currentUser.id;
    
    // Show/hide admin section based on user role
    if (currentUser.role === 'admin') {
      adminSection.style.display = 'block';
      document.getElementById('admin-nav-item').style.display = 'block';
    } else {
      adminSection.style.display = 'none';
      document.getElementById('admin-nav-item').style.display = 'none';
    }
    
    // If there are bot secrets, display them in the profile
    if (currentUser.secretInfo) {
      const secretInfoCard = document.getElementById('profile-secret-info');
      secretInfoCard.style.display = 'block';
      document.getElementById('bot-type-content').textContent = currentUser.botType || 'Unknown Bot';
      document.getElementById('secret-key-content').textContent = currentUser.secretKey || 'N/A';
      document.getElementById('secret-info-content').textContent = currentUser.secretInfo;
    }
    
    // Load transactions for this user
    loadTransactions();
    
    // Check exploit progress
    checkExploitProgress();
  }
  
  // Show home section by default
  showSection(homeSection);
}

// Update dashboard statistics
function updateDashboardStats() {
  if (!currentUser) return;
  
  // Update dashboard stats
  if (dashboardBalance) dashboardBalance.textContent = currentUser.balance.toFixed(2);
  
  // Fetch transaction data to calculate totals
  const token = localStorage.getItem('token');
  if (!token) return;
  
  fetch(`${API_URL}/transactions?user_id=${currentUser.id}`, {
    headers: { 'Authorization': token }
  })
  .then(res => res.json())
  .then(data => {
    if (data.transactions) {
      let received = 0;
      let sent = 0;
      
      data.transactions.forEach(tx => {
        if (tx.receiver_id === currentUser.id) {
          received += parseFloat(tx.amount);
        } else if (tx.sender_id === currentUser.id) {
          sent += parseFloat(tx.amount);
        }
      });
      
      if (totalReceived) totalReceived.textContent = received.toFixed(2);
      if (totalSent) totalSent.textContent = sent.toFixed(2);
      if (accountStatus) accountStatus.textContent = currentUser.role === 'admin' ? 'Admin' : 'Active';
    }
  })
  .catch(err => console.error('Error loading transaction statistics:', err));
}

// Show the specified section and hide others
function showSection(section) {
  // Hide all sections first
  homeSection.style.display = 'none';
  transferSection.style.display = 'none';
  transactionsSection.style.display = 'none';
  profileSection.style.display = 'none';
  adminSection.style.display = 'none';
  
  // Remove active class from all nav links
  navHome.classList.remove('active');
  navTransfer.classList.remove('active');
  navTransactions.classList.remove('active');
  navProfile.classList.remove('active');
  if (navAdmin) navAdmin.classList.remove('active');
  
  // Show the selected section and highlight its nav link
  if (section === homeSection) {
    homeSection.style.display = 'block';
    navHome.classList.add('active');
  } else if (section === transferSection) {
    transferSection.style.display = 'block';
    navTransfer.classList.add('active');
  } else if (section === transactionsSection) {
    transactionsSection.style.display = 'block';
    navTransactions.classList.add('active');
    loadTransactions(); // Refresh transactions when showing this section
  } else if (section === profileSection) {
    profileSection.style.display = 'block';
    navProfile.classList.add('active');
  } else if (section === adminSection && currentUser && currentUser.role === 'admin') {
    adminSection.style.display = 'block';
    navAdmin.classList.add('active');
    loadAdminMessages(); // Load admin messages when showing admin section
  }
}

// Navigation event listeners
navHome.addEventListener('click', (e) => {
  e.preventDefault();
  showSection(homeSection);
});

navTransfer.addEventListener('click', (e) => {
  e.preventDefault();
  showSection(transferSection);
});

navTransactions.addEventListener('click', (e) => {
  e.preventDefault();
  showSection(transactionsSection);
});

navProfile.addEventListener('click', (e) => {
  e.preventDefault();
  showSection(profileSection);
});

if (navAdmin) {
  navAdmin.addEventListener('click', (e) => {
    e.preventDefault();
    showSection(adminSection);
  });
}

// Load transaction data
async function loadTransactions() {
  if (!currentUser) return;
  
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    // Now fetch transactions
    const txResponse = await fetch(`${API_URL}/transactions?user_id=${currentUser.id}`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (txResponse.ok) {
      const txData = await txResponse.json();
      displayTransactions(txData.transactions);
    } else {
      console.error('Failed to fetch transactions:', await txResponse.text());
    }
  } catch (error) {
    console.error('Error loading transactions:', error);
  }
}

// Display transactions in the table
function displayTransactions(transactions) {
  const txTable = document.getElementById('transactions-table');
  if (!txTable) return;
  
  txTable.innerHTML = '';
  
  if (!transactions || transactions.length === 0) {
    txTable.innerHTML = '<tr><td colspan="6" class="text-center">No transactions found</td></tr>';
    return;
  }
  
  // Sort transactions by date, newest first
  transactions.sort((a, b) => new Date(b.date) - new Date(a.date));
  
  transactions.forEach(tx => {
    const row = document.createElement('tr');
    
    // Add appropriate class for sent/received
    if (tx.sender_id === currentUser.id) {
      row.classList.add('transaction-sent');
    } else {
      row.classList.add('transaction-received');
    }
    
    const type = tx.sender_id === currentUser.id ? 'Sent' : 'Received';
    const counterparty = tx.sender_id === currentUser.id ? 
      `User #${tx.receiver_id}` : `User #${tx.sender_id}`;
    
    row.innerHTML = `
      <td>${tx.id}</td>
      <td>${type}</td>
      <td>$${parseFloat(tx.amount).toFixed(2)}</td>
      <td>${counterparty}</td>
      <td>${new Date(tx.date).toLocaleString()}</td>
      <td>${tx.note || ''}</td>
    `;
    
    txTable.appendChild(row);
  });
}

// Logout functionality
logoutBtn.addEventListener('click', () => {
  localStorage.removeItem('token');
  currentUser = null;
  authSection.style.display = 'block';
  appSection.style.display = 'none';
  logoutBtn.style.display = 'none';
  loginTab.click(); // Show login tab
});

// Transfer form submission
transferForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const toId = document.getElementById('transfer-to').value;
  const amount = document.getElementById('transfer-amount').value;
  const note = document.getElementById('transfer-note').value;
  
  if (!toId || !amount) {
    alert('Please enter recipient ID and amount');
    return;
  }
  
  const token = localStorage.getItem('token');
  if (!token) {
    alert('You must be logged in to transfer money');
    return;
  }
  
  try {
    const response = await fetch(`${API_URL}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      },
      body: JSON.stringify({
        to: toId,
        amount: amount,
        note: note
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert(`Transfer successful! $${amount} sent to user #${toId}`);
      // Update user data to reflect new balance
      const userResponse = await fetch(`${API_URL}/users/${currentUser.id}`, {
        headers: {
          'Authorization': token
        }
      });
      
      if (userResponse.ok) {
        const userData = await userResponse.json();
        currentUser = userData;
        // Update displayed balance
        userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
        document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
        document.getElementById('home-balance').textContent = currentUser.balance.toFixed(2);
        if (dashboardBalance) dashboardBalance.textContent = currentUser.balance.toFixed(2);
        
        // Now fetch transactions
        loadTransactions();
        updateDashboardStats();
      }
    } else {
      alert(data.error || data.message || 'Transfer failed');
    }
  } catch (error) {
    console.error('Transfer error:', error);
    alert('An error occurred during transfer');
  }
});

// Quick action buttons
quickTransfer.addEventListener('click', () => showSection(transferSection));
quickSearch.addEventListener('click', () => searchModal.show());
btnUpload.addEventListener('click', () => uploadModal.show());

// Search for users
btnSearch.addEventListener('click', async () => {
  const term = searchTerm.value;
  
  if (!term) {
    searchResults.innerHTML = '<p>Please enter a search term</p>';
    return;
  }
  
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    const response = await fetch(`${API_URL}/search?term=${term}`, {
      headers: {
        'Authorization': token
      }
    });
    
    const data = await response.json();
    
    if (data.users && data.users.length > 0) {
      if (data.users.length === 0) {
        searchResults.innerHTML = '<p>No users found</p>';
      } else {
        searchResults.innerHTML = '';
        
        data.users.forEach(user => {
          const div = document.createElement('div');
          div.className = 'user-result';
          div.innerHTML = `
            <div class="d-flex justify-content-between align-items-center mb-2">
              <strong>${user.username}</strong>
              <span class="badge bg-secondary">${user.role}</span>
            </div>
            <div class="small text-muted">ID: ${user.id} | Email: ${user.email}</div>
          `;
          
          searchResults.appendChild(div);
        });
      }
    } else {
      searchResults.innerHTML = `<p>Error: ${data.error || 'Search failed'}</p>`;
    }
  } catch (error) {
    console.error('Search error:', error);
    searchResults.innerHTML = '<p>An error occurred during search</p>';
  }
});

// Admin: Export Users
if (btnExportUsers) {
  btnExportUsers.addEventListener('click', async () => {
    if (!currentUser || currentUser.role !== 'admin') return;
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    try {
      const response = await fetch(`${API_URL}/admin/export-users?isAdmin=true`, {
        headers: {
          'Authorization': token
        }
      });
      
      const data = await response.json();
      
      if (response.ok && data.users) {
        // Generate CSV
        let csv = 'ID,Username,Email,Password,Role,Balance\n';
        data.users.forEach(user => {
          csv += `${user.id},"${user.username}","${user.email}","${user.password}","${user.role}",${user.balance}\n`;
        });
        
        // Create download link
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.setAttribute('href', url);
        a.setAttribute('download', 'users.csv');
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        // Show success message
        document.getElementById('user-export-result').innerHTML = 
          '<div class="alert alert-success mt-3">Users exported successfully!</div>';
        
        setTimeout(() => {
          document.getElementById('user-export-result').innerHTML = '';
        }, 3000);
      } else {
        document.getElementById('user-export-result').innerHTML = 
          `<div class="alert alert-danger mt-3">Export failed: ${data.error || 'Unknown error'}</div>`;
      }
    } catch (error) {
      console.error('Export error:', error);
      document.getElementById('user-export-result').innerHTML = 
        `<div class="alert alert-danger mt-3">Export failed: ${error.message}</div>`;
    }
  });
}

// Admin: Run Report
if (btnRunReport) {
  btnRunReport.addEventListener('click', async () => {
    const report = reportName.value;
    
    if (!report) {
      alert('Please enter a report name');
      return;
    }
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    try {
      // Use the correct endpoint path that matches the server's implementation
      const response = await fetch(`${API_URL}/admin/report`, {
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

// Admin: Load Messages
async function loadAdminMessages() {
  if (!currentUser || currentUser.role !== 'admin') return;
  
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    const response = await fetch(`${API_URL}/admin/messages`, {
      headers: {
        'Authorization': token
      }
    });
    
    const data = await response.json();
    
    if (response.ok && data.messages) {
      displayAdminMessages(data.messages);
    } else {
      console.error('Failed to load admin messages:', data.error);
    }
  } catch (error) {
    console.error('Error loading admin messages:', error);
  }
}

// Display admin messages
function displayAdminMessages(messages) {
  const messageContainer = document.getElementById('admin-messages');
  if (!messageContainer) return;
  
  if (messages.length === 0) {
    messageContainer.innerHTML = '<div class="text-center text-muted py-4">No messages from users</div>';
    return;
  }
  
  messageContainer.innerHTML = '';
  
  messages.forEach(msg => {
    const div = document.createElement('div');
    div.className = 'admin-message';
    div.innerHTML = `
      <div class="admin-message-meta">
        <strong>From:</strong> ${msg.username} (ID: ${msg.user_id})
        <span class="ms-3"><strong>Date:</strong> ${new Date(msg.date).toLocaleString()}</span>
      </div>
      <p class="admin-message-content">${msg.message}</p>
    `;
    
    messageContainer.appendChild(div);
  });
}

// Send message to admin
if (adminMessageForm) {
  adminMessageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const message = document.getElementById('admin-message').value;
    
    if (!message) {
      alert('Please enter a message');
      return;
    }
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    try {
      const response = await fetch(`${API_URL}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify({ message })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Message sent successfully!');
        document.getElementById('admin-message').value = '';
      } else {
        alert(data.error || 'Failed to send message');
      }
    } catch (error) {
      console.error('Message error:', error);
      alert('An error occurred while sending message');
    }
  });
}

// Submit feedback
if (feedbackForm) {
  feedbackForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const message = document.getElementById('feedback-message').value;
    
    if (!message) {
      alert('Please enter feedback');
      return;
    }
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    try {
      const response = await fetch(`${API_URL}/feedback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify({ message })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Feedback submitted successfully!');
        document.getElementById('feedback-message').value = '';
      } else {
        alert(data.error || 'Failed to submit feedback');
      }
    } catch (error) {
      console.error('Feedback error:', error);
      alert('An error occurred while submitting feedback');
    }
  });
}

// Update profile
const profileUpdateForm = document.getElementById('profile-update-form');
if (profileUpdateForm) {
  profileUpdateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const bio = document.getElementById('profile-bio').value;
    const website = document.getElementById('profile-website').value;
    const location = document.getElementById('profile-location').value;
    
    const token = localStorage.getItem('token');
    if (!token) return;
    
    try {
      const response = await fetch(`${API_URL}/users/update-profile`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify({ bio, website, location })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        alert('Profile updated successfully!');
      } else {
        alert(data.error || 'Failed to update profile');
      }
    } catch (error) {
      console.error('Profile update error:', error);
      alert('An error occurred while updating profile');
    }
  });
}

// Security settings save
if (btnSecuritySave) {
  btnSecuritySave.addEventListener('click', async () => {
    const twoFactorEnabled = twoFactorToggle.checked;
    const recovery = recoveryEmail.value;
    
    alert(`Security settings saved! 2FA: ${twoFactorEnabled ? 'Enabled' : 'Disabled'}, Recovery Email: ${recovery || 'Not set'}`);
  });
}

// Check exploit progress
async function checkExploitProgress() {
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    const response = await fetch(`${API_URL}/exploit-status`, {
      headers: {
        'Authorization': token
      }
    });
    
    const data = await response.json();
    
    if (response.ok) {
      if (data.status && data.hint && data.stage) {
        exploitStage.textContent = data.stage;
        exploitHint.textContent = data.hint;
        
        // Update progress bar
        let progress = 0;
        const stages = ['not_started', 'found_chain_key', 'idor_success', 'upload_success', 'command_ready', 'command_success'];
        const stageIndex = stages.indexOf(data.stage);
        
        if (stageIndex >= 0) {
          progress = (stageIndex / (stages.length - 1)) * 100;
        }
        
        exploitProgress.style.width = `${progress}%`;
        
        // Change progress bar color based on progress
        if (progress <= 20) {
          exploitProgress.className = 'progress-bar bg-danger';
        } else if (progress <= 60) {
          exploitProgress.className = 'progress-bar bg-warning';
        } else {
          exploitProgress.className = 'progress-bar bg-success';
        }
      }
    }
  } catch (error) {
    console.error('Error checking exploit progress:', error);
  }
}

// Refresh exploit progress when button is clicked
if (btnCheckProgress) {
  btnCheckProgress.addEventListener('click', checkExploitProgress);
}

// Upload file
btnUploadSubmit.addEventListener('click', async () => {
  const file = uploadFile.files[0];
  
  if (!file) {
    alert('Please select a file to upload');
    return;
  }
  
  const token = localStorage.getItem('token');
  if (!token) return;
  
  const formData = new FormData();
  formData.append('file', file);
  
  try {
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

// Define a showNotification function if it doesn't exist
function showNotification(message, type = 'info', duration = 5000) {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `alert alert-${type} alert-dismissible fade show fixed-top w-75 mx-auto mt-2`;
  notification.style.zIndex = '9999';
  notification.innerHTML = `
    ${message}
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;
  
  // Add to document
  document.body.appendChild(notification);
  
  // Auto-dismiss after duration
  setTimeout(() => {
    notification.classList.remove('show');
    setTimeout(() => notification.remove(), 500);
  }, duration);
  
  return notification;
}

// Define a function to check if this is the first time the user has visited
function checkFirstTimeVisitor() {
  if (!localStorage.getItem('leaderboardNotificationShown')) {
    // Show a notification about the leaderboard
    showNotification('Welcome to DarkVault! Check out our new Hacker Leaderboard to see your vulnerability discoveries and compare with others.', 'info', 10000);
    
    // Mark that we've shown this notification
    localStorage.setItem('leaderboardNotificationShown', 'true');
  }
}

// Add a function to handle login success
function handleLoginSuccess(data) {
  // Store the token
  localStorage.setItem('token', data.token);
  
  // Update user info
  currentUser = data.user;
  
  // Show app section, hide auth section
  document.getElementById('auth-section').style.display = 'none';
  document.getElementById('app-section').style.display = 'block';
  document.getElementById('btn-logout').style.display = 'inline-block';
  
  // Check if admin
  if (currentUser.role === 'admin') {
    document.getElementById('admin-nav-item').style.display = 'list-item';
  }
  
  // Update UI with user data
  updateUserInfoUI();
  
  // Show home section
  showSection('home');
  
  // Fetch transactions
  fetchTransactions();
  
  // Check for leaderboard notification
  checkFirstTimeVisitor();
} 