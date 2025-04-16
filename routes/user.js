// Vulnerable privilege escalation through parameter manipulation
// Demonstrates broken access control and parameter tampering
router.post('/update-role', (req, res) => {
  const { userId, newRole } = req.body;
  
  // Vulnerable: No proper authorization check, only checking if user is logged in
  if (!req.session.userId) {
    return res.status(401).json({ error: 'You must be logged in' });
  }
  
  // Vulnerable: No validation that the user has admin rights to change roles
  // Also vulnerable to parameter tampering as client controls both userId and newRole
  
  db.query(`UPDATE users SET role = '${newRole}' WHERE id = ${userId}`, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Information disclosure - confirms the operation was successful
    return res.json({ 
      success: true, 
      message: `User role updated to ${newRole}`,
      affectedUser: userId,
      changedBy: req.session.userId
    });
  });
});

// Race condition vulnerability demonstration
let currentPromoCode = 'DARKV50';
let promoUsageCount = 0;
const MAX_PROMO_USES = 5;

router.post('/apply-promo', (req, res) => {
  const { promoCode } = req.body;
  
  if (promoCode !== currentPromoCode) {
    return res.status(400).json({ error: 'Invalid promo code' });
  }
  
  // Race condition vulnerability:
  // Check if promo code has been used too many times
  if (promoUsageCount >= MAX_PROMO_USES) {
    return res.status(400).json({ error: 'Promo code usage limit reached' });
  }
  
  // Vulnerable part - no lock mechanism between check and increment
  // This creates a time gap where multiple requests can pass the check
  // before the counter is actually incremented
  
  // Simulate some processing time that increases the race condition window
  setTimeout(() => {
    // Increment usage count
    promoUsageCount++;
    
    // Apply discount to user account
    const discount = 50; // $50 off
    
    // Log the usage
    console.log(`Promo code used by user ${req.session.userId}. Usage count: ${promoUsageCount}`);
    
    res.json({ 
      success: true, 
      message: `$${discount} discount applied to your account!`,
      usageCount: promoUsageCount,
      maxUses: MAX_PROMO_USES
    });
  }, 1000); // 1 second delay to make race condition more likely
}); 