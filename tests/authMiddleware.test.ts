import { parseExpression } from '@babel/parser';
import { isAuthMiddleware, isAuthMiddlewareName, splitWords } from '../src/parser/adapters/authMiddleware';

const expr = (src: string) => isAuthMiddleware(parseExpression(src, { plugins: ['typescript'] }));

describe('splitWords', () => {
  it('splits camelCase, snake_case and acronyms', () => {
    expect(splitWords('requireAuth')).toEqual(['require', 'auth']);
    expect(splitWords('ensure_logged_in')).toEqual(['ensure', 'logged', 'in']);
    expect(splitWords('verifyJWTToken')).toEqual(['verify', 'jwt', 'token']);
    expect(splitWords('oauthCallback')).toEqual(['oauth', 'callback']);
  });
});

describe('isAuthMiddlewareName', () => {
  it.each([
    'auth',
    'requireAuth',
    'authenticate',
    'isAuthenticated',
    'ensureAuthenticated',
    'authorize',
    'authorization',
    'authMiddleware',
    'jwt',
    'jwtAuth',
    'expressjwt',
    'requireLogin',
    'ensureLoggedIn',
    'protect',
    'protected',
    'passportJwt',
    'verifyToken',
    'check_auth',
    'checkAuth',
    'requireUser',
    'requireRole',
    'isAdmin',
    'requireSession',
    'ensureSession',
    'verifySession',
    'requireApiKey',
    'requireauth',
    'requireStaff',
    'isStaff',
    'ensureStaff',
    'checkStaff',
    'staffOnly',
    'only_staff',
    'isSuperuser',
    'requireSuperuser',
    'isSuperAdmin',
    'requireSuperadmin',
    'requireBackoffice',
    'isBackoffice',
    'isModerator',
    'requireModerator',
    'requirestaff',
    'isstaff',
  ])('recognises %s', (name) => {
    expect(isAuthMiddlewareName(name)).toBe(true);
  });

  it.each([
    'author',
    'authors',
    'authorName',
    'authorsController',
    'oauthCallback',
    'oauth',
    'validate',
    'validateBody',
    'validateAuth',
    'validateLogin',
    'upload',
    'rateLimiter',
    'limiter',
    'authLimiter',
    'loginLimiter',
    'loginRules',
    'cors',
    'bodyParser',
    'logger',
    'asyncHandler',
    'cache',
    'session',
    'sessionMiddleware',
    'user',
    'getUser',
    'validateUser',
    'admin',
    'adminRoutes',
    'authRoutes',
    'authRouter',
    'usersRouter',
    'passwordReset',
    'handler',
    'staff',
    'staffList',
    'getStaff',
    'moderator',
    'moderatorRoutes',
    'backoffice',
    'backofficeRouter',
    'superuser',
    'staffController',
  ])('does not recognise %s', (name) => {
    expect(isAuthMiddlewareName(name)).toBe(false);
  });
});

describe('isAuthMiddleware (expressions)', () => {
  it.each([
    'requireAuth',
    "passport.authenticate('jwt')",
    "passport.authenticate('jwt', { session: false })",
    "authorize('admin')",
    'jwt({ secret: s })',
    'expressjwt({ secret: s, algorithms: ["HS256"] })',
    'auth.required',
    'auth.protect()',
    'middleware.auth',
    'middlewares.authenticate()',
    "requireRole('admin')",
    '[validate, requireAuth]',
    'requireAuth as RequestHandler',
  ])('recognises %s', (src) => {
    expect(expr(src)).toBe(true);
  });

  it.each([
    'validate',
    "upload.single('f')",
    'rateLimiter',
    'limiter',
    'cors()',
    'express.json()',
    'bodyParser.json()',
    'bodyParser',
    'logger',
    'asyncHandler',
    'asyncHandler(authController.login)',
    "cache('5 min')",
    'auth.optional',
    'passport.initialize()',
    'passport.session()',
    '(req, res, next) => next()',
    'authors.list',
    'oauthCallback',
    '[validate, upload.single("f")]',
    '[...mws]',
  ])('does not recognise %s', (src) => {
    expect(expr(src)).toBe(false);
  });
});
