document.addEventListener('DOMContentLoaded', function() {
    // Initialize WebSocket connection
    initWebSocket();
    
    // Set up navigation
    setupNavigation();
    
    // Load initial data
    loadDashboardData();
    
    // Set up event listeners
    setupEventListeners();
});

// WebSocket connection
let socket;
let sessionId = getCookie('neonddos_session');
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = function() {
        console.log('WebSocket connection established');
        reconnectAttempts = 0;
        
        // Authenticate WebSocket connection
        if (sessionId) {
            socket.send(JSON.stringify({
                type: 'auth',
                sessionId: sessionId
            }));
        }
        
        // Subscribe to data updates
        socket.send(JSON.stringify({
            type: 'subscribe',
            event: 'stats'
        }));
    };
    
    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    socket.onclose = function() {
        console.log('WebSocket connection closed');
        
        // Try to reconnect
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            reconnectAttempts++;
            setTimeout(initWebSocket, 3000 * reconnectAttempts);
        } else {
            showAlert('Connection to server lost. Please refresh the page.', 'danger');
        }
    };
    
    socket.onerror = function(error) {
        console.error('WebSocket error:', error);
    };
}

function handleWebSocketMessage(data) {
    switch(data.type) {
        case 'auth':
            handleAuthResponse(data);
            break;
            
        case 'stats':
            updateDashboardStats(data);
            break;
            
        case 'attackData':
            updateAttackData(data);
            break;
            
        case 'connectionData':
            updateConnectionData(data);
            break;
            
        case 'attackAlert':
            showAttackAlert(data);
            break;
            
        case 'statsUpdate':
            updateLiveStats(data);
            break;
            
        case 'error':
            showAlert(data.message, 'danger');
            break;
    }
}

// Navigation setup
function setupNavigation() {
    const navLinks = document.querySelectorAll('.sidebar-nav a');
    const sections = document.querySelectorAll('.content-section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetSection = this.getAttribute('data-section');
            
            // Update navigation
            document.querySelectorAll('.sidebar-nav li').forEach(item => {
                item.classList.remove('active');
            });
            this.parentElement.classList.add('active');
            
            // Update section display
            sections.forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(targetSection).classList.add('active');
            
            // Update section title
            document.getElementById('section-title').textContent = 
                this.querySelector('span').textContent;
        });
    });
    
    // Set up sidebar toggle
    document.getElementById('sidebar-toggle').addEventListener('click', function() {
        document.querySelector('.sidebar').classList.toggle('collapsed');
    });
}

// More code will be added here for handling data, charts, etc.