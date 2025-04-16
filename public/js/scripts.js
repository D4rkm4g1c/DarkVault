// DarkVault main JavaScript file

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('DarkVault application initialized');
  
  // Initialize Bootstrap components
  initBootstrapComponents();
  
  // Setup message deletion confirmation
  setupMessageDeleteConfirmation();
  
  // Setup flag submission
  setupFlagSubmission();
  
  // Setup search functionality
  setupSearch();
  
  // Setup command form
  setupCommandForm();
  
  // Setup password visibility toggle
  setupPasswordToggle();
});

// Initialize Bootstrap components
function initBootstrapComponents() {
  // Fix for dropdown issues in navbar
  const dropdownElementList = document.querySelectorAll('.dropdown-toggle');
  if (dropdownElementList.length > 0) {
    try {
      const dropdownList = [...dropdownElementList].map(dropdownToggleEl => {
        return new bootstrap.Dropdown(dropdownToggleEl);
      });
    } catch (error) {
      console.error('Error initializing dropdowns:', error);
    }
  }
  
  // Ensure the navbar toggler works on mobile
  const navbarToggler = document.querySelector('.navbar-toggler');
  if (navbarToggler) {
    navbarToggler.addEventListener('click', function() {
      const target = document.querySelector(this.getAttribute('data-bs-target'));
      if (target) {
        target.classList.toggle('show');
      } else {
        // Fallback for cases where data-bs-target might be missing
        const navbarNav = document.getElementById('navbarNav');
        if (navbarNav) {
          navbarNav.classList.toggle('show');
        }
      }
    });
  }
  
  // Fix for any broken links by attaching click handlers
  const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
  navLinks.forEach(link => {
    if (link.getAttribute('href') === '#' || !link.getAttribute('href')) {
      link.addEventListener('click', function(e) {
        // Prevent default only if the href is # or empty
        e.preventDefault();
        console.log('Clicked on nav link with missing or # href');
      });
    }
  });
}

// Message deletion confirmation
function setupMessageDeleteConfirmation() {
  const deleteButtons = document.querySelectorAll('.delete-message-btn');
  if (deleteButtons) {
    deleteButtons.forEach(button => {
      button.addEventListener('click', function(e) {
        if (!confirm('Are you sure you want to delete this message?')) {
          e.preventDefault();
        }
      });
    });
  }
}

// Flag submission
function setupFlagSubmission() {
  const flagForm = document.getElementById('flag-form');
  if (flagForm) {
    flagForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const flag = document.getElementById('flag-input').value;
      
      fetch('/check-flag', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ flag: flag }),
      })
      .then(response => response.json())
      .then(data => {
        const resultElement = document.getElementById('flag-result');
        resultElement.textContent = data.message;
        resultElement.className = data.success ? 'alert alert-success' : 'alert alert-danger';
        resultElement.style.display = 'block';
      })
      .catch(error => {
        console.error('Error:', error);
      });
    });
  }
}

// Search functionality
function setupSearch() {
  const searchForm = document.getElementById('search-form');
  if (searchForm) {
    searchForm.addEventListener('submit', function(e) {
      const searchInput = document.getElementById('search-input');
      if (!searchInput.value.trim()) {
        e.preventDefault();
        alert('Please enter a search term');
      }
    });
  }
}

// Command form
function setupCommandForm() {
  const commandForm = document.getElementById('command-form');
  if (commandForm) {
    commandForm.addEventListener('submit', function(e) {
      const cmdInput = document.getElementById('command-input');
      if (!cmdInput.value.trim()) {
        e.preventDefault();
        alert('Please enter a command');
      }
    });
  }
}

// Password visibility toggle
function setupPasswordToggle() {
  const togglePasswordBtn = document.getElementById('toggle-password');
  if (togglePasswordBtn) {
    togglePasswordBtn.addEventListener('click', function() {
      const passwordInput = document.getElementById('password');
      const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
      passwordInput.setAttribute('type', type);
      this.textContent = type === 'password' ? 'Show' : 'Hide';
    });
  }
} 