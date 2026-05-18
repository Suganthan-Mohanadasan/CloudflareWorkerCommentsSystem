import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verify as jwtVerify } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// Import converted services
import { CommentService } from './services/comment.service';
import { ProjectService } from './services/project.service';
import { AuthService } from './services/auth.service';
import { EmailService } from './services/email.service';
import { UserService } from './services/user.service';
import { PageService } from './services/page.service';
import { TokenService } from './services/token.service';
import { UsageService } from './services/usage.service';
import { SubscriptionService } from './services/subscription.service';
import { NotificationService } from './services/notification.service';

export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  ASSETS: Fetcher;
  JWT_SECRET: string;
  TURNSTILE_SECRET: string;
  // AWS SES outbound. Used by EmailService to send moderation notifications.
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_REGION?: string;
  // FROM_EMAIL is the verified SES sender (e.g. comments@suganthan.com), set in vars.
  FROM_EMAIL?: string;
  SITE_URL: string;
}

// Cloudflare Turnstile server-side verification.
// Called from the public POST /api/open/comments handler to block automated abuse
// before any DB write happens. Token comes from the widget's Turnstile challenge.
async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  form.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: form,
  });
  const json = await res.json() as { success: boolean };
  return json.success === true;
}

const app = new Hono<{ Bindings: Env }>();

// CORS: locked to the production domain, www variant, and the test subdomain.
// The widget is loaded as an iframe from the comments host onto these origins,
// so they are the only origins that need cross-origin access to the API.
const ALLOWED_ORIGINS = [
  'https://suganthan.com',
  'https://www.suganthan.com',
  'https://comments.suganthan.com',
  // Keep the test origin alive for now so old email magic links and any open
  // tabs still hitting the test host don't break. Drop once nothing in flight.
  'https://comments-test.suganthan.com',
];
app.use('*', cors({
  origin: (origin) => (origin && ALLOWED_ORIGINS.includes(origin) ? origin : null),
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Timezone-Offset'],
}));

// (Catch-all GET handler for static assets / SPA / widget.js is registered at the
//  END of this file. Hono matches routes by registration order, so it must come
//  after the specific API GET routes or it will shadow them.)

// Widget routes
async function handleWidgetRoutes(c: any) {
  const url = new URL(c.req.url);
  
  if (url.pathname === '/js/cusdis.es.js') {
    const script = `
(function() {
  var CUSDIS_LOCALE = window.CUSDIS_LOCALE || {};
  
  function renderCusdis(target, attrs) {
    var appId = attrs['data-app-id'];
    var pageId = attrs['data-page-id'];
    var pageUrl = attrs['data-page-url'] || window.location.href;
    var pageTitle = attrs['data-page-title'] || document.title;
    var theme = attrs['data-theme'] || 'light';
    var host = attrs['data-host'] || '${c.env.SITE_URL}';
    
    if (!appId) {
      console.error('Cusdis: data-app-id is required');
      return;
    }
    
    var iframe = document.createElement('iframe');
    iframe.src = host + '/widget.html?appId=' + encodeURIComponent(appId) + 
                 '&pageId=' + encodeURIComponent(pageId || pageUrl) +
                 '&pageUrl=' + encodeURIComponent(pageUrl) +
                 '&pageTitle=' + encodeURIComponent(pageTitle) +
                 '&theme=' + encodeURIComponent(theme);
    iframe.style.width = '100%';
    iframe.style.border = 'none';
    iframe.style.minHeight = '200px';
    iframe.id = 'cusdis-iframe';
    
    target.appendChild(iframe);
    
    // Auto-resize iframe
    window.addEventListener('message', function(e) {
      if (e.origin !== '${new URL(c.env.SITE_URL).origin}') return;
      if (e.data.type === 'cusdis-resize') {
        iframe.style.height = e.data.height + 'px';
      }
    });
  }
  
  function init() {
    var targets = document.querySelectorAll('#cusdis_thread');
    targets.forEach(function(target) {
      renderCusdis(target, target.dataset);
    });
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  window.CUSDIS = {
    renderTo: renderCusdis
  };
})();
    `;
    
    return new Response(script, {
      headers: {
        'Content-Type': 'application/javascript',
        'Cache-Control': 'public, max-age=86400',
      },
    });
  }
  
  return c.notFound();
}

// API Routes

// Authentication
// Registration is closed. The first admin was registered against sugan@basicgravity.com
// during initial deploy. Any further registration is rejected. To re-enable
// (e.g. to add another moderator), remove this 403 and redeploy.
app.post('/api/auth/register', async (c) => {
  throw new HTTPException(403, { message: 'Registration is closed' });
});

app.post('/api/auth/login', async (c) => {
  const authService = new AuthService(c.env);
  const body = await c.req.json();
  
  try {
    const result = await authService.login(body.email, body.password);
    return c.json(result);
  } catch (error: any) {
    throw new HTTPException(401, { message: error.message });
  }
});

// JWT middleware for protected routes.
//
// Note: hono/jwt's built-in `jwt()` middleware takes the secret at INIT time and
// does not invoke it as a function later, so the upstream `secret: async (c) => c.env.JWT_SECRET`
// shipped broken (every protected request 401'd). Hand-rolled here so the secret
// is read from c.env at request time, where it actually exists.
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.raw.headers.get('Authorization');
  if (!authHeader) {
    throw new HTTPException(401, { message: 'Missing Authorization header' });
  }
  const parts = authHeader.split(/\s+/);
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    throw new HTTPException(401, { message: 'Invalid Authorization header' });
  }
  const token = parts[1];
  try {
    const payload = await jwtVerify(token, c.env.JWT_SECRET);
    c.set('jwtPayload', payload);
  } catch (e) {
    throw new HTTPException(401, { message: 'Invalid token' });
  }
  await next();
};

// Public API routes (for embedded widget)
app.get('/api/open/comments', async (c) => {
  const commentService = new CommentService(c.env);
  const projectService = new ProjectService(c.env);
  
  const appId = c.req.query('appId');
  const pageId = c.req.query('pageId');
  const page = parseInt(c.req.query('page') || '1');
  const timezoneOffset = parseInt(c.req.header('X-Timezone-Offset') || '0');
  
  if (!appId || !pageId) {
    throw new HTTPException(400, { message: 'appId and pageId are required' });
  }
  
  const isDeleted = await projectService.isDeleted(appId);
  if (isDeleted) {
    return c.json({
      data: {
        commentCount: 0,
        data: [],
        pageCount: 0,
        pageSize: 10,
      }
    });
  }
  
  const comments = await commentService.getComments(appId, timezoneOffset, {
    approved: true,
    parentId: null,
    pageSlug: pageId,
    page,
    pageSize: 10,
  });
  
  return c.json({ data: comments });
});

app.post('/api/open/comments', async (c) => {
  const commentService = new CommentService(c.env);
  const projectService = new ProjectService(c.env);
  const emailService = new EmailService(c.env);

  const body = await c.req.json();
  const { appId, pageId, content, email, nickname, parentId, acceptNotify, pageTitle, pageUrl } = body;
  const turnstileToken = body['cf-turnstile-response'];

  // Verify Turnstile BEFORE any DB writes. Rejects bots that did not solve the
  // challenge widget. Missing token = 400, failed verify = 403.
  if (!turnstileToken) {
    throw new HTTPException(400, { message: 'Missing anti-bot token' });
  }
  const ip = c.req.header('CF-Connecting-IP') || '';
  const ok = await verifyTurnstile(turnstileToken, c.env.TURNSTILE_SECRET, ip);
  if (!ok) {
    throw new HTTPException(403, { message: 'Anti-bot check failed' });
  }

  if (!appId || !pageId || !content || !nickname) {
    throw new HTTPException(400, { message: 'Missing required fields' });
  }

  const isDeleted = await projectService.isDeleted(appId);
  if (isDeleted) {
    throw new HTTPException(404, { message: 'Project not found' });
  }
  
  const comment = await commentService.addComment(appId, pageId, {
    content,
    email,
    nickname,
    pageTitle,
    pageUrl,
  }, parentId);

  // Fire the moderator notification email. This was dead code upstream —
  // NotificationService.addComment was defined but never called from this handler.
  try {
    const notificationService = new NotificationService(c.env);
    await notificationService.addComment(comment, appId);
  } catch (error) {
    // Never fail the comment submission because email failed. Log and move on.
    console.error('Failed to send moderator notification:', error);
  }

  // Reply-confirm email for the COMMENTER who opted in to "notify me on replies".
  if (acceptNotify && email) {
    try {
      await emailService.sendConfirmReplyNotification(email, pageTitle || pageId, comment.id);
    } catch (error) {
      console.error('Failed to send confirmation email:', error);
    }
  }

  return c.json({ data: comment });
});

// Open approve route (for email approval links)
app.get('/api/open/approve', async (c) => {
  const commentService = new CommentService(c.env);
  const tokenService = new TokenService(c.env);

  const token = c.req.query('token');

  if (!token) {
    return c.text('Invalid token', 400);
  }

  try {
    const result = await tokenService.validateApproveToken(token);
    await commentService.approve(result.commentId);
    return c.text('Approved!');
  } catch (error) {
    return c.text('Invalid token', 403);
  }
});

// Open delete route (for email "delete spam" links). Soft-deletes the comment;
// row stays in D1 with deleted_at set, never re-surfaces in the public widget.
app.get('/api/open/delete', async (c) => {
  const commentService = new CommentService(c.env);
  const tokenService = new TokenService(c.env);

  const token = c.req.query('token');

  if (!token) {
    return c.text('Invalid token', 400);
  }

  try {
    const result = await tokenService.validateDeleteToken(token);
    await commentService.delete(result.commentId);
    return c.text('Deleted.');
  } catch (error) {
    return c.text('Invalid token', 403);
  }
});

app.post('/api/open/approve', async (c) => {
  const commentService = new CommentService(c.env);
  const tokenService = new TokenService(c.env);
  const usageService = new UsageService(c.env);
  const subscriptionService = new SubscriptionService(c.env);
  
  const token = c.req.query('token');
  const body = await c.req.json();
  const { replyContent } = body;
  
  if (!token) {
    throw new HTTPException(403, { message: 'Invalid token' });
  }
  
  let tokenBody;
  try {
    tokenBody = await tokenService.validateApproveToken(token);
  } catch (error) {
    throw new HTTPException(403, { message: 'Invalid token' });
  }
  
  // Check usage limits
  const canQuickApprove = await subscriptionService.quickApproveValidate(tokenBody.ownerId);
  if (!canQuickApprove) {
    throw new HTTPException(402, { 
      message: 'You have reached the maximum number of Quick Approve on free plan. Please upgrade to Pro plan to use Quick Approve more.' 
    });
  }
  
  // Approve comment
  await commentService.approve(tokenBody.commentId);
  
  // Add reply if provided
  if (replyContent && replyContent.trim()) {
    await commentService.addCommentAsModerator(tokenBody.commentId, replyContent, tokenBody.ownerId);
  }
  
  // Increment usage
  await usageService.incrementQuickApprove(tokenBody.ownerId);
  
  return c.json({ message: 'success' });
});

// Get comment for approval page
app.get('/api/open/approve/comment', async (c) => {
  const commentService = new CommentService(c.env);
  const tokenService = new TokenService(c.env);
  
  const token = c.req.query('token');
  
  if (!token) {
    throw new HTTPException(400, { message: 'Token is required' });
  }
  
  try {
    const tokenData = await tokenService.validateApproveToken(token);
    const comment = await commentService.getCommentForApproval(tokenData.commentId);
    return c.json({ comment });
  } catch (error) {
    throw new HTTPException(403, { message: 'Invalid token' });
  }
});

// Get comment counts for multiple pages
app.get('/api/open/project/:projectId/comments/count', async (c) => {
  const projectId = c.req.param('projectId');
  const pageIds = c.req.query('pageIds');
  
  if (!pageIds) {
    throw new HTTPException(400, { message: 'pageIds parameter is required' });
  }
  
  const pageIdArray = pageIds.split(',');
  const data: Record<string, number> = {};
  
  // Get counts for each page ID
  for (const pageId of pageIdArray) {
    const result = await c.env.DB.prepare(`
      SELECT COUNT(c.id) as count
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      WHERE p.slug = ? AND p.project_id = ? AND c.deleted_at IS NULL AND c.approved = 1
    `).bind(pageId, projectId).first() as any;
    
    data[pageId] = result?.count || 0;
  }
  
  return c.json({ data });
});

// Get latest comments for a project with token authentication
app.get('/api/open/project/:projectId/comments/latest', async (c) => {
  const projectService = new ProjectService(c.env);
  const projectId = c.req.param('projectId');
  const token = c.req.query('token');
  
  if (!token) {
    throw new HTTPException(403, { message: 'Invalid token' });
  }
  
  // Verify project token
  const project = await c.env.DB.prepare(`
    SELECT token, fetch_latest_comments_at
    FROM projects 
    WHERE id = ?
  `).bind(projectId).first() as any;
  
  if (!project || project.token !== token) {
    throw new HTTPException(403, { message: 'Invalid token' });
  }
  
  const comments = await projectService.fetchLatestComment(projectId, {
    from: project.fetch_latest_comments_at ? new Date(project.fetch_latest_comments_at) : undefined,
    markAsRead: true
  });
  
  return c.json({ comments });
});

// Protected routes
app.use('/api/projects/*', authMiddleware);
app.use('/api/comment/*', authMiddleware);
app.use('/api/user/*', authMiddleware);

// Projects API
app.get('/api/projects', async (c) => {
  const projectService = new ProjectService(c.env);
  const payload = c.get('jwtPayload');
  
  const projects = await projectService.listByOwner(payload.sub);
  return c.json({ data: projects });
});

app.post('/api/projects', async (c) => {
  const projectService = new ProjectService(c.env);
  const userService = new UserService(c.env);
  const payload = c.get('jwtPayload');
  const body = await c.req.json();
  
  const canCreate = await userService.canCreateProject(payload.sub);
  if (!canCreate) {
    throw new HTTPException(402, { 
      message: 'You have reached the maximum number of sites on free plan.' 
    });
  }
  
  const project = await projectService.create(body.title, payload.sub);
  return c.json({ data: project });
});

app.get('/api/project/:id', async (c) => {
  const projectService = new ProjectService(c.env);
  const payload = c.get('jwtPayload');
  const projectId = c.req.param('id');
  
  const project = await projectService.getByIdAndOwner(projectId, payload.sub);
  if (!project) {
    throw new HTTPException(404, { message: 'Project not found' });
  }
  
  return c.json({ data: project });
});

// Comments API (admin).
//
// Upstream had `onlyOwn: true` here, but the comment.service `onlyOwn` branch
// appends `AND pr.owner_id = ?` to the WHERE clause without binding a param,
// which 500s every admin list. Fixed by checking project ownership up front
// against the JWT payload and then listing without onlyOwn.
//
// Supports ?approved=0|1 to filter pending vs approved.
app.get('/api/comment', async (c) => {
  const commentService = new CommentService(c.env);
  const projectService = new ProjectService(c.env);
  const payload = c.get('jwtPayload');
  const projectId = c.req.query('projectId');
  const approvedParam = c.req.query('approved');
  const page = parseInt(c.req.query('page') || '1');
  const timezoneOffset = parseInt(c.req.header('X-Timezone-Offset') || '0');

  if (!projectId) {
    throw new HTTPException(400, { message: 'projectId is required' });
  }

  const project = await projectService.getByIdAndOwner(projectId, payload.sub);
  if (!project) {
    throw new HTTPException(404, { message: 'Project not found' });
  }

  const opts: any = { page, pageSize: 20 };
  if (approvedParam === '0') opts.approved = false;
  if (approvedParam === '1') opts.approved = true;

  const comments = await commentService.getComments(projectId, timezoneOffset, opts);

  return c.json({ data: comments });
});

app.post('/api/comment/:id/approve', async (c) => {
  const commentService = new CommentService(c.env);
  const payload = c.get('jwtPayload');
  const commentId = c.req.param('id');
  
  const project = await commentService.getProject(commentId);
  if (project.ownerId !== payload.sub) {
    throw new HTTPException(403, { message: 'Forbidden' });
  }
  
  await commentService.approve(commentId);
  return c.json({ success: true });
});

app.delete('/api/comment/:id', async (c) => {
  const commentService = new CommentService(c.env);
  const payload = c.get('jwtPayload');
  const commentId = c.req.param('id');
  
  const project = await commentService.getProject(commentId);
  if (project.ownerId !== payload.sub) {
    throw new HTTPException(403, { message: 'Forbidden' });
  }
  
  await commentService.delete(commentId);
  return c.json({ success: true });
});

app.post('/api/comment/:id/reply', async (c) => {
  const commentService = new CommentService(c.env);
  const payload = c.get('jwtPayload');
  const commentId = c.req.param('id');
  const body = await c.req.json();
  
  const project = await commentService.getProject(commentId);
  if (project.ownerId !== payload.sub) {
    throw new HTTPException(403, { message: 'Forbidden' });
  }
  
  const reply = await commentService.addCommentAsModerator(commentId, body.content, payload.sub);
  return c.json({ data: reply });
});

// User API
app.get('/api/user', async (c) => {
  const userService = new UserService(c.env);
  const payload = c.get('jwtPayload');
  
  const user = await userService.getById(payload.sub);
  return c.json({ data: user });
});

app.put('/api/user', async (c) => {
  const userService = new UserService(c.env);
  const payload = c.get('jwtPayload');
  const body = await c.req.json();
  
  const user = await userService.updateProfile(payload.sub, body);
  return c.json({ data: user });
});

app.get('/api/user/stats', async (c) => {
  const userService = new UserService(c.env);
  const payload = c.get('jwtPayload');
  
  const stats = await userService.getStats(payload.sub);
  return c.json(stats);
});

// Catch-all GET handler. Registered LAST so specific API GET routes (above) are
// matched first by Hono. Serves the embed script, then static assets via the
// ASSETS binding, then a fallback SPA shell for frontend routes.
app.get('*', async (c) => {
  const url = new URL(c.req.url);

  // API path should never reach here in normal operation (specific routes match
  // earlier). Return 404 if it does — a bare /api/foo with no matching handler.
  if (url.pathname.startsWith('/api/')) {
    return c.notFound();
  }

  // Embed script served from the worker so the appId / host are interpolated.
  if (url.pathname.startsWith('/js/')) {
    return await handleWidgetRoutes(c);
  }

  // Static assets (dist/ + frontend/public/) via the ASSETS binding.
  try {
    const response = await c.env.ASSETS.fetch(c.req.raw);
    console.log('ASSETS response status:', response.status, 'for path:', url.pathname);
    if (response.status < 500) {
      return response;
    }
  } catch (error) {
    console.log('Assets fetch failed:', error);
  }

  // SPA fallback for admin frontend routes.
  const frontendRoutes = ['/dashboard', '/login', '/projects', '/getting-start', '/forbidden', '/error'];
  const isFrontendRoute = frontendRoutes.some(route => url.pathname.startsWith(route)) || url.pathname === '/';

  if (isFrontendRoute) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cusdis - Lightweight, privacy-first, open-source comment system</title>
    <link rel="icon" href="/favicon.ico" />
  <script type="module" crossorigin src="/assets/index-4ed4436d.js"></script>
  <link rel="stylesheet" href="/assets/index-4efb08a1.css">
</head>
<body>
    <div id="root"></div>

</body>
</html>`;

    return c.html(html);
  }

  return c.notFound();
});

// Error handling
app.onError((err, c) => {
  console.error('Error:', err);
  
  if (err instanceof HTTPException) {
    return c.json({ error: err.message }, err.status);
  }
  
  return c.json({ error: 'Internal Server Error' }, 500);
});

export default app;