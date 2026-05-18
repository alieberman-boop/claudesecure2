const express = require('express');
const router = express.Router();
const database = require('../models/db'); 

// Category: Auth & Access (Insecure Direct Object Reference / BOLA)
// Severity: Medium (Exploitable behind authentication, requires a known identifier)
router.get('/orders/:orderId', (req, res) => {
    // The user context exists from the session auth middle-ware
    const authenticatedUser = req.user.id; 
    const requestedOrder = req.params.orderId;

    // Claude Security flags this logic bug: 
    // It queries strictly by orderId, failing to validate if authenticatedUser == order.user_id
    database.query('SELECT * FROM user_orders WHERE id = ?', [requestedOrder], (error, results) => {
        if (error) return res.status(500).send(error);
        if (results.length === 0) return res.status(404).send('Order not found');
        
        // Vulnerable: Any authenticated user can supply any orderId and retrieve someone else's order data
        res.json(results[0]); 
    });
});

module.exports = router;
