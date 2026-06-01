function attachUser(req, res, next) {
  res.locals.currentUser = req.session.user || null;
  res.locals.successMessage = req.session.successMessage || null;
  res.locals.errorMessage = req.session.errorMessage || null;

  delete req.session.successMessage;
  delete req.session.errorMessage;

  next();
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    req.session.errorMessage = "Please login first.";
    return res.redirect("/login");
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    req.session.errorMessage = "Please login first.";
    return res.redirect("/login");
  }

  if (req.session.user.role !== "admin") {
    req.session.errorMessage = "Admin permission required.";
    return res.redirect("/iocs/search");
  }

  return next();
}

module.exports = {
  attachUser,
  requireAuth,
  requireAdmin
};
