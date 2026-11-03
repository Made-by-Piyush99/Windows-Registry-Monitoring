// Admin Dashboard Management Logic
let allFeedbacks = [];
let activeFilter = 'all';
let searchQuery = '';

// Check Auth on load
document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('regmonitor_admin_token');
  const user = JSON.parse(localStorage.getItem('regmonitor_admin_user') || 'null');

  if (token && user) {
    showDashboard(user);
    fetchFeedbacks();
  } else {
    showLogin();
  }
});

// Switch Views
function showLogin() {
  document.getElementById('admin-login-view').style.display = 'block';
  document.getElementById('admin-dashboard-view').style.display = 'none';
  document.getElementById('auth-nav-items').style.display = 'none';
}

function showDashboard(user) {
  document.getElementById('admin-login-view').style.display = 'none';
  document.getElementById('admin-dashboard-view').style.display = 'block';
  document.getElementById('auth-nav-items').style.display = 'flex';
  document.getElementById('admin-user-display').textContent = `👤 ${user.name || user.email}`;
}

// Show Toast Notification
function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  const toastText = document.getElementById('toast-text');
  const toastIcon = document.getElementById('toast-icon');

  toastText.textContent = message;
  toastIcon.textContent = isError ? '⚠' : '✓';
  if (isError) {
    toast.classList.add('error');
  } else {
    toast.classList.remove('error');
  }

  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3500);
}

// Handle Admin Login
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value.trim();
  const btnLogin = document.getElementById('btn-login');

  btnLogin.disabled = true;
  btnLogin.innerHTML = '<span>⏳ Authenticating...</span>';

  try {
    const res = await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      localStorage.setItem('regmonitor_admin_token', data.token);
      localStorage.setItem('regmonitor_admin_user', JSON.stringify(data.user));
      showToast('Login successful. Welcome back!');
      showDashboard(data.user);
      fetchFeedbacks();
    } else {
      showToast(data.error || 'Invalid credentials.', true);
    }
  } catch (err) {
    console.error('Login error:', err);
    showToast('Failed to connect to authentication server.', true);
  } finally {
    btnLogin.disabled = false;
    btnLogin.innerHTML = '<span>🔓 Sign In to Admin Console</span>';
  }
}

// Handle Logout
function handleLogout() {
  localStorage.removeItem('regmonitor_admin_token');
  localStorage.removeItem('regmonitor_admin_user');
  showToast('Logged out successfully.');
  showLogin();
}

// Fetch all feedbacks from serverless API
async function fetchFeedbacks() {
  const container = document.getElementById('feedbacks-container');
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon">⏳</div>
      <h3>Fetching feedback data...</h3>
      <p>Synchronizing with encrypted cloud store.</p>
    </div>
  `;

  try {
    const res = await fetch('/api/feedback');
    const data = await res.json();

    if (res.ok && data.success) {
      allFeedbacks = data.feedbacks || [];
      updateKPIs();
      renderFeedbacks();
    } else {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">⚠</div>
          <h3>Failed to load feedbacks</h3>
          <p>${data.error || 'Could not retrieve data.'}</p>
        </div>
      `;
    }
  } catch (err) {
    console.error('Fetch error:', err);
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">📡</div>
        <h3>Network Error</h3>
        <p>Could not connect to database endpoint.</p>
      </div>
    `;
  }
}

// Update KPI Ribbon Cards
function updateKPIs() {
  const total = allFeedbacks.length;
  const students = allFeedbacks.filter(f => f.type === 'student');
  const companies = allFeedbacks.filter(f => f.type === 'company');
  const withSuggestions = allFeedbacks.filter(f => ((f.implementationSuggestions || f.suggestions || '')).trim());

  // Averages
  const avgStudent = students.length > 0 
    ? (students.reduce((acc, curr) => acc + (curr.rating || 5), 0) / students.length).toFixed(1) 
    : '0.0';

  const avgCompany = companies.length > 0 
    ? (companies.reduce((acc, curr) => acc + (curr.rating || 5), 0) / companies.length).toFixed(1) 
    : '0.0';

  // Set Elements
  document.getElementById('kpi-total').textContent = total;
  document.getElementById('kpi-total-sub').textContent = `${total} verified reviews`;
  document.getElementById('kpi-students').textContent = students.length;
  document.getElementById('kpi-student-rating').textContent = `Avg Rating: ${avgStudent} ★`;
  document.getElementById('kpi-companies').textContent = companies.length;
  document.getElementById('kpi-company-rating').textContent = `Avg Rating: ${avgCompany} ★`;
  document.getElementById('kpi-suggestions').textContent = withSuggestions.length;
  document.getElementById('kpi-suggestions-sub').textContent = `${withSuggestions.length} feature ideas`;

  // Filter badge counts
  document.getElementById('count-all').textContent = total;
  document.getElementById('count-student').textContent = students.length;
  document.getElementById('count-company').textContent = companies.length;
  document.getElementById('count-suggestions').textContent = withSuggestions.length;
}

// Set active filter
function setFilter(filter) {
  activeFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  
  if (filter === 'all') document.getElementById('filter-all').classList.add('active');
  if (filter === 'student') document.getElementById('filter-student').classList.add('active');
  if (filter === 'company') document.getElementById('filter-company').classList.add('active');
  if (filter === 'suggestions') document.getElementById('filter-suggestions').classList.add('active');

  renderFeedbacks();
}

function toggleImplementationFilter() {
  setFilter(activeFilter === 'suggestions' ? 'all' : 'suggestions');
}

// Search filter
function handleSearch(query) {
  searchQuery = query.toLowerCase().trim();
  renderFeedbacks();
}

// Render feedback cards
function renderFeedbacks() {
  const container = document.getElementById('feedbacks-container');
  const showingText = document.getElementById('showing-text');

  // Filter list
  let filtered = allFeedbacks.filter(fb => {
    // Role filter
    if (activeFilter === 'student' && fb.type !== 'student') return false;
    if (activeFilter === 'company' && fb.type !== 'company') return false;
    const suggText = (fb.implementationSuggestions || fb.suggestions || '').trim();
    if (activeFilter === 'suggestions' && !suggText) return false;

    // Search query filter
    if (searchQuery) {
      const matchName = (fb.name || '').toLowerCase().includes(searchQuery);
      const matchEmail = (fb.email || '').toLowerCase().includes(searchQuery);
      const matchOrg = ((fb.institution || '') + ' ' + (fb.company || '')).toLowerCase().includes(searchQuery);
      const matchSuggestions = suggText.toLowerCase().includes(searchQuery);
      const matchTestimonial = (fb.testimonial || '').toLowerCase().includes(searchQuery);
      return matchName || matchEmail || matchOrg || matchSuggestions || matchTestimonial;
    }

    return true;
  });

  showingText.textContent = `Showing ${filtered.length} of ${allFeedbacks.length} records`;

  if (filtered.length === 0) {
    if (allFeedbacks.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📥</div>
          <h3>No Submissions Yet (Clean Live State)</h3>
          <p>Zero fake or mock users. Real student and enterprise evaluation submissions will appear here live in real-time.</p>
        </div>
      `;
      return;
    }
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔍</div>
        <h3>No Feedback Matching Current Criteria</h3>
        <p>Try clearing your search query or switching the filter.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(fb => createFeedbackCardHTML(fb)).join('');
}

// Build Card HTML for an entry
function createFeedbackCardHTML(fb) {
  const isStudent = fb.type === 'student';
  const avatarLetter = (fb.name || 'U').charAt(0).toUpperCase();
  const dateStr = fb.createdAt ? new Date(fb.createdAt).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }) : 'Recent';

  // Stars generator
  const renderStars = (rating) => '★'.repeat(rating || 5) + '☆'.repeat(Math.max(0, 5 - (rating || 5)));

  // Badges row
  let badges = [];
  if (isStudent) {
    if (fb.readiness) badges.push(`<span class="tag-badge">🏆 ${escapeHTML(fb.readiness)}</span>`);
    if (Array.isArray(fb.favoriteFeatures)) {
      fb.favoriteFeatures.forEach(f => badges.push(`<span class="tag-badge">${escapeHTML(f)}</span>`));
    }
  } else {
    if (fb.hireability) badges.push(`<span class="tag-badge">🚀 ${escapeHTML(fb.hireability)}</span>`);
    if (Array.isArray(fb.enterpriseRecommendations)) {
      fb.enterpriseRecommendations.forEach(r => badges.push(`<span class="tag-badge">🌐 ${escapeHTML(r)}</span>`));
    }
  }

  // Implementation Highlight HTML
  let implementationHTML = '';
  const suggestionContent = (fb.implementationSuggestions || fb.suggestions || '').trim();
  if (suggestionContent) {
    implementationHTML = `
      <div class="fb-implementation-highlight">
        <h5>💡 Implementation Suggestion ("Kaha Kya Implement Karna Hai"):</h5>
        <p>${escapeHTML(suggestionContent)}</p>
      </div>
    `;
  }

  // Testimonial HTML
  let testimonialHTML = '';
  if (fb.testimonial && fb.testimonial.trim()) {
    testimonialHTML = `
      <div class="fb-testimonial">
        "${escapeHTML(fb.testimonial)}"
      </div>
    `;
  }

  return `
    <div class="fb-card" id="card-${fb.id}">
      <div class="fb-header">
        <div class="fb-user">
          <div class="fb-avatar ${isStudent ? 'student' : 'company'}">
            ${avatarLetter}
          </div>
          <div class="fb-user-info">
            <h4>${escapeHTML(fb.name)}</h4>
            <p>${isStudent ? `🎓 ${escapeHTML(fb.institution || 'Student')}` : `🏢 ${escapeHTML(fb.company || 'Company')} • ${escapeHTML(fb.designation || 'Professional')}`}</p>
            <p style="font-size: 0.78rem; color: var(--text-dim);">${escapeHTML(fb.email)}</p>
          </div>
        </div>

        <div class="fb-meta-right">
          <span class="role-pill ${isStudent ? 'student' : 'company'}">
            ${isStudent ? '🎓 Student Review' : '🏢 Company Review'}
          </span>
          <span class="fb-date">${dateStr}</span>
        </div>
      </div>

      <!-- Ratings Breakdown -->
      <div class="fb-ratings-bar">
        <div class="rating-item">
          <strong>Overall:</strong>
          <span class="stars">${renderStars(fb.rating)}</span>
          <span>(${fb.rating || 5}/5)</span>
        </div>
        ${isStudent ? `
          <div class="rating-item">
            <strong>Concept Clarity:</strong>
            <span class="stars">${renderStars(fb.conceptClarity)}</span>
          </div>
          <div class="rating-item">
            <strong>UI Polish:</strong>
            <span class="stars">${renderStars(fb.uiRating)}</span>
          </div>
        ` : `
          <div class="rating-item">
            <strong>Practicality:</strong>
            <span class="stars">${renderStars(fb.practicality)}</span>
          </div>
          <div class="rating-item">
            <strong>Security Arch:</strong>
            <span class="stars">${renderStars(fb.securityRating)}</span>
          </div>
        `}
      </div>

      <!-- Implementation Suggestions Highlight -->
      ${implementationHTML}

      <!-- Testimonial Quote -->
      ${testimonialHTML}

      <!-- Footer Badges and Delete Action -->
      <div class="fb-badges-row">
        ${badges.join('')}
        <button class="btn-delete" onclick="deleteFeedback('${fb.id}')" title="Delete this entry">
          🗑️ Delete
        </button>
      </div>
    </div>
  `;
}

// Delete feedback
async function deleteFeedback(id) {
  if (!confirm('Are you sure you want to delete this feedback entry? This action cannot be undone.')) {
    return;
  }

  try {
    const res = await fetch(`/api/feedback?id=${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });

    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Feedback deleted successfully.');
      allFeedbacks = allFeedbacks.filter(f => f.id !== id);
      updateKPIs();
      renderFeedbacks();
    } else {
      showToast(data.error || 'Failed to delete feedback.', true);
    }
  } catch (err) {
    console.error('Delete error:', err);
    showToast('Failed to connect to delete endpoint.', true);
  }
}

// Export all data to CSV
function exportCSV() {
  if (allFeedbacks.length === 0) {
    showToast('No feedback data to export.', true);
    return;
  }

  const headers = [
    'ID', 'Date', 'Type', 'Name', 'Email', 'Organization', 'Role/Course',
    'Overall Rating', 'Concept Clarity/Practicality', 'UI/Security Rating',
    'Readiness/Hireability', 'Implementation Suggestions', 'Testimonial'
  ];

  const rows = allFeedbacks.map(f => [
    f.id,
    f.createdAt || '',
    f.type,
    `"${(f.name || '').replace(/"/g, '""')}"`,
    `"${(f.email || '').replace(/"/g, '""')}"`,
    `"${(f.institution || f.company || '').replace(/"/g, '""')}"`,
    `"${(f.course || f.designation || '').replace(/"/g, '""')}"`,
    f.rating || 5,
    f.conceptClarity || f.practicality || 5,
    f.uiRating || f.securityRating || 5,
    `"${(f.readiness || f.hireability || '').replace(/"/g, '""')}"`,
    `"${(f.implementationSuggestions || f.suggestions || '').replace(/"/g, '""')}"`,
    `"${(f.testimonial || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `RegistryMonitor_Feedback_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast('Exported to CSV successfully!');
}

// Export all data to JSON
function exportJSON() {
  if (allFeedbacks.length === 0) {
    showToast('No feedback data to export.', true);
    return;
  }

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(allFeedbacks, null, 2));
  const link = document.createElement('a');
  link.setAttribute('href', dataStr);
  link.setAttribute('download', `RegistryMonitor_Feedback_${Date.now()}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast('Exported to JSON successfully!');
}

// Helper: Escape HTML string
function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
