import { Env } from '../index';
import { EmailService } from './email.service';
import { TokenService } from './token.service';

export class NotificationService {
  private emailService: EmailService;
  private tokenService: TokenService;

  constructor(private env: Env) {
    this.emailService = new EmailService(env);
    this.tokenService = new TokenService(env);
  }

  async addComment(comment: any, projectId: string) {
    // Don't notify if comment is created by moderator
    if (comment.moderator_id) {
      return;
    }

    // Check if project and owner have notifications enabled
    const project = await this.env.DB.prepare(`
      SELECT 
        pr.enable_notification,
        u.id as owner_id,
        u.email,
        u.enable_new_comment_notification,
        u.notification_email
      FROM projects pr
      INNER JOIN users u ON pr.owner_id = u.id
      WHERE pr.id = ? AND pr.deleted_at IS NULL
    `).bind(projectId).first() as any;

    if (!project?.enable_notification || !project.enable_new_comment_notification) {
      return;
    }

    // Get full comment details
    const fullComment = await this.env.DB.prepare(`
      SELECT 
        p.title as page_title,
        p.slug as page_slug,
        pr.title as project_title
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      WHERE c.id = ?
    `).bind(comment.id).first() as any;

    if (!fullComment) {
      return;
    }

    const notificationEmail = project.notification_email || project.email;

    try {
      const approveToken = await this.tokenService.genApproveToken(comment.id);
      const deleteToken = await this.tokenService.genDeleteToken(comment.id);

      await this.emailService.sendNewCommentNotification(
        notificationEmail,
        fullComment.project_title,
        fullComment.page_title || fullComment.page_slug,
        comment.content,
        comment.by_nickname,
        // Upstream wrote /open/approve (no /api). Real endpoint is /api/open/approve.
        `${this.env.SITE_URL}/api/open/approve?token=${approveToken}`,
        `${this.env.SITE_URL}/api/open/delete?token=${deleteToken}`,
        `${this.env.SITE_URL}/dashboard`
      );

      console.log('Notification email sent to:', notificationEmail);
    } catch (error) {
      console.error('Failed to send notification email:', error);
    }
  }

  async sendReplyNotification(parentComment: any, reply: any) {
    // Only notify if parent comment author provided email and accepted notifications
    if (!parentComment.by_email || !parentComment.accept_notify) {
      return;
    }

    // Get page info
    const pageInfo = await this.env.DB.prepare(`
      SELECT p.title, p.url
      FROM pages p
      WHERE p.id = ?
    `).bind(parentComment.page_id).first() as any;

    if (!pageInfo) {
      return;
    }

    try {
      const unsubscribeToken = await this.tokenService.genUnsubscribeNewCommentToken(parentComment.id);

      await this.emailService.sendReplyNotification(
        parentComment.by_email,
        pageInfo.title || 'the page',
        parentComment.content,
        reply.content,
        reply.by_nickname,
        pageInfo.url || `${this.env.SITE_URL}`,
        `${this.env.SITE_URL}/api/open/unsubscribe?token=${unsubscribeToken}`
      );

      console.log('Reply notification sent to:', parentComment.by_email);
    } catch (error) {
      console.error('Failed to send reply notification:', error);
    }
  }
}