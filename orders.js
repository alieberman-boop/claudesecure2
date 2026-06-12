const express = require('express');
const router = express.Router();
const database = require('../models/db'); 

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
