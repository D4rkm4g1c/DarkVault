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
const navExploits = document.getElementById('nav-exploits');
const navAdmin = document.getElementById('nav-admin');
const adminSection = document.getElementById('admin-section');
const homeSection = document.getElementById('home-section');
const transferSection = document.getElementById('transfer-section');
const transactionsSection = document.getElementById('transactions-section');
const profileSection = document.getElementById('profile-section');
const exploitsSection = document.getElementById('exploits-section');
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

// Exploit chain elements
const exploitProgress = document.getElementById('exploit-progress');
const exploitStage = document.getElementById('exploit-stage');
const exploitHint = document.getElementById('exploit-hint');
const btnCheckProgress = document.getElementById('btn-check-progress');

// Check if there's a message in URL (vulnerable to XSS)
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const message = urlParams.get('message');
  
  if (message) {
    messageBanner.style.display = 'block';
    // Vulnerable to XSS - directly injecting parameter into innerHTML
    // Example: http://localhost:3000/?message=<script>alert(document.cookie)</script>
    // Can be used to steal cookies, inject fake login forms, redirect users, etc.
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
      // Store token in localStorage
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
    // This ensures we see the bot secrets when using a bot token
    const response = await fetch(`${API_URL}/users/${userId}`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const userData = await response.json();
      currentUser = userData;
      showLoggedInState();
      
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
        showSection(document.getElementById('profile-section'));
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
  
  // Update user info display
  const username = currentUser.username;
  document.getElementById('summary-username').textContent = username;
  document.getElementById('summary-balance').textContent = currentUser.balance.toFixed(2);
  document.getElementById('summary-role').textContent = currentUser.role;
  document.getElementById('summary-role-badge').textContent = currentUser.role;
  document.getElementById('summary-id').textContent = currentUser.id;
  
  // Set user initial (first letter of username)
  document.getElementById('user-initial').textContent = username.charAt(0).toUpperCase();
  
  userBalance.textContent = `Balance: $${currentUser.balance.toFixed(2)}`;
  
  // Update profile section
  document.getElementById('profile-id').textContent = currentUser.id;
  document.getElementById('profile-username').textContent = currentUser.username;
  document.getElementById('profile-email').textContent = currentUser.email;
  document.getElementById('profile-role').textContent = currentUser.role;
  
  // Display bot secrets if available
  const secretInfoElement = document.getElementById('profile-secret-info');
  if (secretInfoElement) {
    if (currentUser.secretInfo) {
      secretInfoElement.style.display = 'block';
      document.getElementById('secret-info-content').textContent = currentUser.secretInfo;
      document.getElementById('secret-key-content').textContent = currentUser.secretKey || 'N/A';
      document.getElementById('bot-type-content').textContent = currentUser.botType || 'N/A';
    } else {
      secretInfoElement.style.display = 'none';
    }
  }
  
  // Set user ID for messaging (vulnerable to parameter tampering)
  messageUserId.value = currentUser.id;
  
  // Show admin section if admin
  if (currentUser.role === 'admin') {
    adminSection.style.display = 'block';
  }
  
  // Check exploit chain progress
  checkExploitProgress();
  
  // Show home section by default
  showSection(homeSection);
  
  // Load transactions
  loadTransactions();
  
  // Add event listener for quick balance transfer button
  const quickBalanceTransfer = document.getElementById('quick-balance-transfer');
  if (quickBalanceTransfer) {
    quickBalanceTransfer.addEventListener('click', () => showSection(transferSection));
  }
}

// Navigation
navHome.addEventListener('click', () => showSection(homeSection));
navTransfer.addEventListener('click', () => showSection(transferSection));
navTransactions.addEventListener('click', () => {
  loadTransactions();
  showSection(transactionsSection);
});
navProfile.addEventListener('click', () => showSection(profileSection));
navExploits.addEventListener('click', () => showSection(exploitsSection));
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

// Add feedback button in navbar
document.querySelector('.navbar-brand').addEventListener('click', function(e) {
  e.preventDefault();
  const feedbackModal = new bootstrap.Modal(document.getElementById('feedbackModal'));
  feedbackModal.show();
});

// Submit feedback - vulnerable to stored XSS in headless browser
document.getElementById('btn-feedback-submit').addEventListener('click', async () => {
  const email = document.getElementById('feedback-email').value;
  const message = document.getElementById('feedback-message').value;
  const rating = document.getElementById('feedback-rating').value;
  
  try {
    const response = await fetch(`${API_URL}/feedback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, message, rating })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      alert('Thank you for your feedback! An admin will review it shortly.');
      bootstrap.Modal.getInstance(document.getElementById('feedbackModal')).hide();
    } else {
      alert(data.error || 'Failed to submit feedback');
    }
  } catch (error) {
    console.error('Feedback error:', error);
    alert('An error occurred while submitting feedback');
  }
});

// Handle profile update - vulnerable to second-order SQL injection
document.getElementById('profile-update-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const bio = document.getElementById('profile-bio').value;
  const website = document.getElementById('profile-website').value;
  const location = document.getElementById('profile-location').value;
  
  try {
    const token = localStorage.getItem('token');
    
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

// Function to check exploit chain progress
async function checkExploitProgress() {
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    const response = await fetch(`${API_URL}/exploit-status`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      
      // Update the progress bar
      exploitProgress.style.width = data.completion;
      exploitStage.textContent = data.status;
      exploitHint.textContent = data.hint;
      
      // Update completion percentage
      const completionPercentage = document.getElementById('completion-percentage');
      if (completionPercentage) {
        completionPercentage.textContent = data.completion;
      }
      
      // Update stage alert style based on progress
      const stageAlert = document.getElementById('exploit-stage-alert');
      if (stageAlert) {
        // Remove existing alert classes
        stageAlert.classList.remove('alert-dark', 'alert-warning', 'alert-info', 'alert-success');
        
        // Apply appropriate class based on completion
        if (data.completion === '100%') {
          stageAlert.classList.add('alert-success');
        } else if (parseInt(data.completion) > 60) {
          stageAlert.classList.add('alert-info');
        } else if (parseInt(data.completion) > 20) {
          stageAlert.classList.add('alert-warning');
        } else {
          stageAlert.classList.add('alert-dark');
        }
      }
      
      // Dynamically update the progress bar color based on completion
      if (data.completion === '100%') {
        exploitProgress.classList.remove('bg-danger', 'bg-warning', 'bg-info');
        exploitProgress.classList.add('bg-success');
      } else if (parseInt(data.completion) > 60) {
        exploitProgress.classList.remove('bg-danger', 'bg-warning', 'bg-success');
        exploitProgress.classList.add('bg-info');
      } else if (parseInt(data.completion) > 20) {
        exploitProgress.classList.remove('bg-danger', 'bg-info', 'bg-success');
        exploitProgress.classList.add('bg-warning');
      }
    }
  } catch (error) {
    console.error('Error checking exploit progress:', error);
  }
}

// Add event listener for the check progress button
if (btnCheckProgress) {
  btnCheckProgress.addEventListener('click', checkExploitProgress);
}

// Exploit Status Page Elements
const refreshExploitsBtn = document.getElementById('refresh-exploits');
const overallProgress = document.getElementById('overall-progress');
const overallCompletion = document.getElementById('overall-completion');
const currentStageDesc = document.getElementById('current-stage-desc');

// Exploit status indicators
const exploitStatusMap = {
  'sql': {
    statusIcon: document.getElementById('sql-status-icon'),
    status: document.getElementById('sql-status'),
    details: document.getElementById('sql-details'),
    hint: document.getElementById('sql-hint')
  },
  'auth': {
    statusIcon: document.getElementById('auth-status-icon'),
    status: document.getElementById('auth-status'),
    details: document.getElementById('auth-details'),
    hint: document.getElementById('auth-hint')
  },
  'idor': {
    statusIcon: document.getElementById('idor-status-icon'),
    status: document.getElementById('idor-status'),
    details: document.getElementById('idor-details'),
    hint: document.getElementById('idor-hint')
  },
  'upload': {
    statusIcon: document.getElementById('upload-status-icon'),
    status: document.getElementById('upload-status'),
    details: document.getElementById('upload-details'),
    hint: document.getElementById('upload-hint')
  },
  'command': {
    statusIcon: document.getElementById('command-status-icon'),
    status: document.getElementById('command-status'),
    details: document.getElementById('command-details'),
    hint: document.getElementById('command-hint')
  }
};

// Event listener for refreshing exploit status
if (refreshExploitsBtn) {
  refreshExploitsBtn.addEventListener('click', updateDetailedExploitStatus);
}

// Add nav-exploits event listener to update exploit status when clicked
if (navExploits) {
  navExploits.addEventListener('click', () => {
    showSection(exploitsSection);
    updateDetailedExploitStatus();
  });
}

// Function to update the detailed exploit status page
async function updateDetailedExploitStatus() {
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    // Get the exploit status data
    const response = await fetch(`${API_URL}/exploit-status`, {
      headers: {
        'Authorization': token
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      
      // Update overall progress indicators
      overallProgress.style.width = data.completion;
      overallCompletion.textContent = data.completion;
      currentStageDesc.textContent = data.status;
      
      // Update each exploit status based on the current stage
      updateExploitCardStatuses(data.current_stage);
      
      // Update the discovered secrets section
      updateDiscoveredSecrets(data);
    }
  } catch (error) {
    console.error('Error updating exploit status:', error);
  }
}

// Function to update the status of each exploit card based on current stage
function updateExploitCardStatuses(currentStage) {
  // Reset all cards to their initial state
  resetExploitCards();
  
  // Update card statuses based on current stage
  switch(currentStage) {
    case 'found_chain_key':
      updateExploitCard('sql', 'success', 'Exploited Successfully', 
        'You have discovered the chain key through SQL injection.', 
        'Now use this key with the x-chain-key header in login');
      break;
      
    case 'idor_success':
      updateExploitCard('sql', 'success', 'Exploited Successfully', 
        'You have discovered the chain key through SQL injection.', 
        'Now use this key with the x-chain-key header in login');
      updateExploitCard('auth', 'success', 'Exploited Successfully', 
        'You have successfully bypassed authentication.', 
        'Now try accessing other user profiles');
      updateExploitCard('idor', 'success', 'Exploited Successfully', 
        'You have successfully accessed other user profiles.', 
        'Look for file upload secrets');
      break;
      
    case 'upload_success':
      updateExploitCard('sql', 'success', 'Exploited Successfully', 
        'You have discovered the chain key through SQL injection.', 
        'Now use this key with the x-chain-key header in login');
      updateExploitCard('auth', 'success', 'Exploited Successfully', 
        'You have successfully bypassed authentication.', 
        'Now try accessing other user profiles');
      updateExploitCard('idor', 'success', 'Exploited Successfully', 
        'You have successfully accessed other user profiles.', 
        'Look for file upload secrets');
      updateExploitCard('upload', 'success', 'Exploited Successfully', 
        'You have successfully uploaded to the executable directory.', 
        'Now look for command injection token');
      break;
      
    case 'command_ready':
      updateExploitCard('sql', 'success', 'Exploited Successfully', 
        'You have discovered the chain key through SQL injection.', 
        'Now use this key with the x-chain-key header in login');
      updateExploitCard('auth', 'success', 'Exploited Successfully', 
        'You have successfully bypassed authentication.', 
        'Now try accessing other user profiles');
      updateExploitCard('idor', 'success', 'Exploited Successfully', 
        'You have successfully accessed other user profiles.', 
        'Look for file upload secrets');
      updateExploitCard('upload', 'success', 'Exploited Successfully', 
        'You have successfully uploaded to the executable directory.', 
        'Now look for command injection token');
      updateExploitCard('command', 'warning', 'Ready to Exploit', 
        'You have all prerequisites for command injection.', 
        'Use x-exploit-token with the admin report endpoint');
      break;
      
    case 'command_success':
      updateExploitCard('sql', 'success', 'Exploited Successfully', 
        'You have discovered the chain key through SQL injection.', 
        'Now use this key with the x-chain-key header in login');
      updateExploitCard('auth', 'success', 'Exploited Successfully', 
        'You have successfully bypassed authentication.', 
        'Now try accessing other user profiles');
      updateExploitCard('idor', 'success', 'Exploited Successfully', 
        'You have successfully accessed other user profiles.', 
        'Look for file upload secrets');
      updateExploitCard('upload', 'success', 'Exploited Successfully', 
        'You have successfully uploaded to the executable directory.', 
        'Now look for command injection token');
      updateExploitCard('command', 'success', 'Exploited Successfully', 
        'You have successfully executed commands on the server.', 
        'Congratulations! You have completed the full exploit chain.');
      break;
      
    default:
      // Not started case - all cards remain in their default state
      break;
  }
}

// Function to reset all exploit cards to their initial state
function resetExploitCards() {
  Object.keys(exploitStatusMap).forEach(key => {
    const card = exploitStatusMap[key];
    if (card.statusIcon) {
      card.statusIcon.innerHTML = '<i class="bi bi-x-circle text-danger fs-1"></i>';
    }
    if (card.status) {
      card.status.textContent = 'Not Exploited';
    }
    if (card.details) {
      let defaultMessage = 'Not yet discovered or exploited.';
      
      switch(key) {
        case 'sql':
          defaultMessage = 'Try exploring the search functionality with SQL injection to find hidden secrets.';
          break;
        case 'auth':
          defaultMessage = 'Requires discovering the chain key through SQL injection first.';
          break;
        case 'idor':
          defaultMessage = 'Need to find the right access token to view other user profiles.';
          break;
        case 'upload':
          defaultMessage = 'Need to discover the executable directory first.';
          break;
        case 'command':
          defaultMessage = 'Requires completing previous steps in the chain.';
          break;
      }
      
      card.details.textContent = defaultMessage;
    }
  });
}

// Function to update a specific exploit card
function updateExploitCard(cardKey, status, statusText, details, hint) {
  const card = exploitStatusMap[cardKey];
  if (!card) return;
  
  if (card.statusIcon) {
    let iconHtml = '<i class="bi bi-x-circle text-danger fs-1"></i>';
    
    if (status === 'success') {
      iconHtml = '<i class="bi bi-check-circle-fill text-success fs-1"></i>';
    } else if (status === 'warning') {
      iconHtml = '<i class="bi bi-exclamation-circle-fill text-warning fs-1"></i>';
    } else if (status === 'info') {
      iconHtml = '<i class="bi bi-info-circle-fill text-info fs-1"></i>';
    }
    
    card.statusIcon.innerHTML = iconHtml;
  }
  
  if (card.status) {
    card.status.textContent = statusText;
  }
  
  if (card.details) {
    card.details.textContent = details;
  }
  
  if (card.hint) {
    card.hint.textContent = hint;
  }
}

// Function to update the discovered secrets section
function updateDiscoveredSecrets(data) {
  const secretsList = document.getElementById('secrets-list');
  const secretsItems = document.getElementById('secrets-items');
  const noSecretsAlert = secretsList.querySelector('.alert-warning');
  
  if (!data.discoveredSecrets || Object.keys(data.discoveredSecrets).length === 0) {
    // No secrets discovered yet
    if (noSecretsAlert) noSecretsAlert.style.display = 'block';
    if (secretsItems) secretsItems.style.display = 'none';
    return;
  }
  
  // Hide the "no secrets" alert and show the list
  if (noSecretsAlert) noSecretsAlert.style.display = 'none';
  if (secretsItems) {
    secretsItems.style.display = 'block';
    secretsItems.innerHTML = '';
    
    // Add each discovered secret to the list
    try {
      const secrets = data.discoveredSecrets || {};
      
      Object.entries(secrets).forEach(([key, value]) => {
        const listItem = document.createElement('li');
        listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
        
        let icon = 'key';
        let secretLabel = key;
        
        switch(key) {
          case 'chain_key':
            icon = 'key-fill';
            secretLabel = 'SQL Injection Chain Key';
            break;
          case 'idor_success':
            icon = 'person-badge-fill';
            secretLabel = 'IDOR Access Token';
            break;
          case 'upload_success':
            icon = 'upload';
            secretLabel = 'File Upload Path';
            break;
          case 'command_injection':
            icon = 'terminal-fill';
            secretLabel = 'Command Injection Token';
            break;
        }
        
        listItem.innerHTML = `
          <div>
            <i class="bi bi-${icon} me-2"></i>
            <strong>${secretLabel}</strong>
            <div class="text-muted"><small>${typeof value === 'string' ? value : JSON.stringify(value)}</small></div>
          </div>
          <span class="badge bg-success rounded-pill">Discovered</span>
        `;
        
        secretsItems.appendChild(listItem);
      });
    } catch (e) {
      console.error('Error parsing discovered secrets:', e);
    }
  }
} 