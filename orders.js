const express = require('express');
const router = express.Router();
const database = require('../models/db');

// CS-006 fix: both id AND user_id must match — prevents horizontal access to other users' orders.
// Returns 404 (not 403) to avoid leaking whether a foreign order ID exists.
router.get('/orders/:orderId', (req, res) => {
    const authenticatedUser = req.user.id;
    const requestedOrder = req.params.orderId;

    database.query(
        'SELECT * FROM user_orders WHERE id = ? AND user_id = ?',
        [requestedOrder, authenticatedUser],
        (error, results) => {
            if (error) return res.status(500).send(error);
            if (results.length === 0) return res.status(404).send('Order not found');
            res.json(results[0]);
        }
    );
});

module.exports = router;
