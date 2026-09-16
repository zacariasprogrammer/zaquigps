const BACKEND_URL = "https://zaquigps.onrender.com";

// Handles both Signup and Signin with 2FA check
async function handleAuthAction(type) {
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value.trim();

    if (!email || !password) return toast("Enter email and password!");

    const endpoint = type === 'signup' ? '/api/auth/signup' : '/api/auth/signin';

    try {
        const res = await fetch(`${BACKEND_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (!res.ok) {
            return toast(data.message || "Auth failed!");
        }

        // Handle 2FA prompt requirement from signin endpoint
        if (data.requires2FA) {
            document.getElementById('authSection').style.display = 'none';
            document.getElementById('twoFactorSection').style.display = 'block';
            return toast("2FA Required! Enter code.");
        }

        // Save Auth State
        currentUser = { email: data.user.email, token: data.token };
        localStorage.setItem('zaqui_user', JSON.stringify(currentUser));
        updateAuthUI();
        toast(type === 'signup' ? "Account Created!" : "Logged In!");
    } catch (err) {
        toast("Unable to connect to auth server.");
    }
}

// Submits TOTP code for accounts with 2FA enabled
async function submitTwoFactorCode() {
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value.trim();
    const twoFactorCode = document.getElementById('twoFactorCode').value.trim();

    if (!twoFactorCode) return toast("Enter 2FA Code!");

    try {
        const res = await fetch(`${BACKEND_URL}/api/auth/signin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, twoFactorCode })
        });
        const data = await res.json();

        if (!res.ok) return toast(data.message || "Invalid 2FA code.");

        currentUser = { email: data.user.email, token: data.token };
        localStorage.setItem('zaqui_user', JSON.stringify(currentUser));
        updateAuthUI();
        toast("2FA Verified & Logged In!");
    } catch (err) {
        toast("Verification server error.");
    }
}

// Request authentic TOTP Secret from backend
async function enable2FASetup() {
    if (!currentUser || !currentUser.token) return toast("Please sign in first!");

    try {
        const res = await fetch(`${BACKEND_URL}/api/auth/setup-2fa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        const data = await res.json();

        if (!res.ok) return toast(data.message || "Failed to generate 2FA key.");

        alert(`Your 2FA Secret Key:\n\nSecret: ${data.secret}\n\nEnter this secret into Google Authenticator or Microsoft Authenticator.`);
    } catch (err) {
        toast("Could not generate 2FA secret.");
    }
}
