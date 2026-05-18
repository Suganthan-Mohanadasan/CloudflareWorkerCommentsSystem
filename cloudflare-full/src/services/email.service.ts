import { Env } from '../index';
import { AwsClient } from 'aws4fetch';

export class EmailService {
  constructor(private env: Env) {}

  // Sends via AWS SES SendEmail (HTTP), signed with SigV4 via aws4fetch.
  // The IAM user attached to AWS_ACCESS_KEY_ID needs ses:SendEmail and the FROM
  // address must be a verified SES identity (domain or single-email).
  async send(options: {
    to: string;
    subject: string;
    html: string;
    from?: string;
  }) {
    if (!this.env.AWS_ACCESS_KEY_ID || !this.env.AWS_SECRET_ACCESS_KEY || !this.env.AWS_REGION) {
      console.warn('AWS SES credentials not configured, email not sent');
      return;
    }

    const fromEmail = options.from || this.env.FROM_EMAIL || 'noreply@suganthan.com';
    const region = this.env.AWS_REGION;

    const aws = new AwsClient({
      accessKeyId: this.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: this.env.AWS_SECRET_ACCESS_KEY,
      service: 'ses',
      region,
    });

    // SES SendEmail is form-encoded. application/x-www-form-urlencoded body
    // with Action + Destination + Message fields. Plain HTML, no attachments
    // so SendEmail is enough (no need for SendRawEmail).
    const body = new URLSearchParams({
      Action: 'SendEmail',
      Version: '2010-12-01',
      Source: fromEmail,
      'Destination.ToAddresses.member.1': options.to,
      'Message.Subject.Data': options.subject,
      'Message.Subject.Charset': 'UTF-8',
      'Message.Body.Html.Data': options.html,
      'Message.Body.Html.Charset': 'UTF-8',
    });

    try {
      const res = await aws.fetch(`https://email.${region}.amazonaws.com/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });

      if (!res.ok) {
        const errorBody = await res.text();
        console.error('SES error:', res.status, errorBody);
        throw new Error(`SES API error: ${res.status}`);
      }

      console.log('Email sent successfully to:', options.to);
    } catch (error) {
      console.error('Failed to send email:', error);
      throw error;
    }
  }

  async sendNewCommentNotification(
    to: string,
    projectTitle: string,
    pageTitle: string,
    commentContent: string,
    commenterName: string,
    approveUrl: string,
    deleteUrl: string,
    dashboardUrl: string
  ) {
    // HTML-escape comment content + nickname so a malicious commenter cannot
    // inject markup into the moderator's inbox.
    const esc = (s: string) => s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>New comment on ${esc(projectTitle)}</h2>
        <p>Pending moderation on "<strong>${esc(pageTitle)}</strong>".</p>

        <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #007cba; margin: 20px 0;">
          <p><strong>${esc(commenterName)}</strong> wrote:</p>
          <p>${esc(commentContent)}</p>
        </div>

        <div style="margin: 30px 0;">
          <a href="${approveUrl}" style="display: inline-block; background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin-right: 10px;">
            Approve
          </a>
          <a href="${deleteUrl}" style="display: inline-block; background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Delete (spam)
          </a>
        </div>

        <p style="color: #666; font-size: 13px;">
          Tokens expire in 3 days. <a href="${dashboardUrl}">Open the admin dashboard</a> to manage existing comments.
        </p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Sent by the suganthan.com comments worker.
        </p>
      </div>
    `;

    await this.send({
      to,
      subject: `New comment on ${projectTitle}: ${commenterName}`,
      html,
    });
  }

  async sendConfirmReplyNotification(
    to: string,
    pageTitle: string,
    commentId: string
  ) {
    const confirmUrl = `${this.env.SITE_URL}/api/open/confirm-reply-notification?token=${this.generateConfirmToken(commentId)}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Confirm Reply Notifications</h2>
        <p>You have requested to receive notifications when someone replies to your comment on "${pageTitle}".</p>
        
        <p>To confirm this subscription, please click the button below:</p>
        
        <div style="margin: 30px 0; text-align: center;">
          <a href="${confirmUrl}" style="display: inline-block; background: #007cba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            Confirm Reply Notifications
          </a>
        </div>
        
        <p style="color: #666; font-size: 14px;">
          If you didn't request this, you can safely ignore this email.
        </p>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This email was sent by Cusdis comment system.
        </p>
      </div>
    `;

    await this.send({
      to,
      subject: `Confirm reply notifications for ${pageTitle}`,
      html,
    });
  }

  async sendReplyNotification(
    to: string,
    pageTitle: string,
    originalContent: string,
    replyContent: string,
    replierName: string,
    pageUrl: string,
    unsubscribeUrl: string
  ) {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>New Reply to Your Comment</h2>
        <p>Someone has replied to your comment on "${pageTitle}":</p>
        
        <div style="background: #f9f9f9; padding: 15px; border-left: 4px solid #ccc; margin: 20px 0;">
          <p><strong>Your comment:</strong></p>
          <p>${originalContent}</p>
        </div>
        
        <div style="background: #f5f5f5; padding: 15px; border-left: 4px solid #007cba; margin: 20px 0;">
          <p><strong>${replierName}</strong> replied:</p>
          <p>${replyContent}</p>
        </div>
        
        <div style="margin: 30px 0; text-align: center;">
          <a href="${pageUrl}" style="display: inline-block; background: #007cba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
            View Conversation
          </a>
        </div>
        
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          Don't want to receive these notifications? 
          <a href="${unsubscribeUrl}">Unsubscribe</a>
        </p>
      </div>
    `;

    await this.send({
      to,
      subject: `New reply on ${pageTitle}`,
      html,
    });
  }

  private generateConfirmToken(commentId: string): string {
    // Simple token generation - in production, consider using JWT or similar
    const data = `${commentId}:${Date.now()}`;
    return btoa(data).replace(/[+/=]/g, '');
  }

  public verifyConfirmToken(token: string): string | null {
    try {
      const decoded = atob(token);
      const [commentId] = decoded.split(':');
      return commentId;
    } catch {
      return null;
    }
  }
}