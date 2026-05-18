import { Env } from '../index';
import { PageService } from './page.service';

export interface CommentItem {
  id: string;
  content: string;
  by_nickname: string;
  by_email?: string;
  created_at: string;
  approved: boolean;
  moderator_id?: string;
  parent_id?: string;
  parsedContent: string;
  parsedCreatedAt: string;
  replies: CommentWrapper;
  page: {
    id: string;
    slug: string;
    title?: string;
  };
  moderator?: {
    display_name?: string;
  };
}

export interface CommentWrapper {
  commentCount: number;
  pageSize: number;
  pageCount: number;
  data: CommentItem[];
}

export class CommentService {
  private pageService: PageService;

  constructor(private env: Env) {
    this.pageService = new PageService(env);
  }

  private escapeHtml(input: string): string {
    // Escape HTML entities before any markdown rendering. Prevents stored XSS
    // by ensuring user content cannot inject tags or attributes.
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  private parseMarkdown(content: string): string {
    // Escape HTML entities FIRST so user input cannot inject tags. Markdown
    // regex patterns (** * `) still match because they do not contain entities.
    const escaped = this.escapeHtml(content);
    return escaped
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
  }

  private formatDate(dateStr: string, timezoneOffset: number): string {
    const date = new Date(dateStr);
    const offsetMs = timezoneOffset * 60 * 1000;
    const adjustedDate = new Date(date.getTime() + offsetMs);
    
    return adjustedDate.toISOString().slice(0, 16).replace('T', ' ');
  }

  async getComments(
    projectId: string,
    timezoneOffset: number,
    options: {
      parentId?: string | null;
      page?: number;
      pageSlug?: string;
      onlyOwn?: boolean;
      approved?: boolean;
      pageSize?: number;
    } = {}
  ): Promise<CommentWrapper> {
    const pageSize = options.pageSize || 10;
    const page = options.page || 1;
    const offset = (page - 1) * pageSize;

    let whereClause = 'WHERE c.deleted_at IS NULL AND p.project_id = ?';
    const params: any[] = [projectId];

    if (options.parentId !== undefined) {
      if (options.parentId === null) {
        whereClause += ' AND c.parent_id IS NULL';
      } else {
        whereClause += ' AND c.parent_id = ?';
        params.push(options.parentId);
      }
    }

    if (options.approved !== undefined) {
      whereClause += ' AND c.approved = ?';
      params.push(options.approved ? 1 : 0);
    }

    if (options.pageSlug) {
      whereClause += ' AND p.slug = ?';
      params.push(options.pageSlug);
    }

    if (options.onlyOwn) {
      whereClause += ' AND pr.owner_id = ?';
      // This would need the user ID, but we'll handle this in the caller
    }

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as count
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      ${whereClause}
    `;

    const countResult = await this.env.DB.prepare(countQuery).bind(...params).first() as any;
    const commentCount = countResult?.count || 0;

    // Get comments
    const commentsQuery = `
      SELECT 
        c.id, c.content, c.by_nickname, c.by_email, c.created_at, 
        c.approved, c.moderator_id, c.parent_id,
        p.id as page_id, p.slug as page_slug, p.title as page_title,
        u.display_name as moderator_display_name
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      LEFT JOIN users u ON c.moderator_id = u.id
      ${whereClause}
      ORDER BY c.created_at DESC
      LIMIT ? OFFSET ?
    `;

    const result = await this.env.DB.prepare(commentsQuery)
      .bind(...params, pageSize, offset)
      .all();

    const comments = result.results as any[];

    // Process comments and get replies
    const processedComments: CommentItem[] = await Promise.all(
      comments.map(async (comment) => {
        const replies = await this.getComments(projectId, timezoneOffset, {
          ...options,
          parentId: comment.id,
          page: 1,
          pageSize: 100, // Load all replies for now
        });

        return {
          id: comment.id,
          content: comment.content,
          by_nickname: comment.by_nickname,
          by_email: comment.by_email,
          created_at: comment.created_at,
          approved: Boolean(comment.approved),
          moderator_id: comment.moderator_id,
          parent_id: comment.parent_id,
          parsedContent: this.parseMarkdown(comment.content),
          parsedCreatedAt: this.formatDate(comment.created_at, timezoneOffset),
          replies,
          page: {
            id: comment.page_id,
            slug: comment.page_slug,
            title: comment.page_title,
          },
          moderator: comment.moderator_display_name ? {
            display_name: comment.moderator_display_name,
          } : undefined,
        };
      })
    );

    const pageCount = Math.ceil(commentCount / pageSize) || 1;

    return {
      data: processedComments,
      commentCount,
      pageSize,
      pageCount,
    };
  }

  async getCommentCount(projectId: string, pageSlug: string): Promise<number> {
    const result = await this.env.DB.prepare(`
      SELECT COUNT(*) as count
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      WHERE p.project_id = ? AND p.slug = ? AND c.approved = 1 AND c.deleted_at IS NULL
    `).bind(projectId, pageSlug).first() as any;

    return result?.count || 0;
  }

  async addComment(
    projectId: string,
    pageSlug: string,
    body: {
      content: string;
      email?: string;
      nickname: string;
      pageUrl?: string;
      pageTitle?: string;
    },
    parentId?: string
  ) {
    // Input validation (rejects empty, too-long, malformed)
    const content = (body.content ?? '').trim();
    if (!content) {
      throw new Error('Comment content is required');
    }
    if (content.length > 5000) {
      throw new Error('Comment too long (max 5000 characters)');
    }

    const nickname = (body.nickname ?? '').trim();
    if (!nickname) {
      throw new Error('Nickname is required');
    }
    if (nickname.length > 100) {
      throw new Error('Nickname too long (max 100 characters)');
    }

    const email = body.email ? body.email.trim() : '';
    if (email) {
      if (email.length > 254) {
        throw new Error('Email too long');
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw new Error('Invalid email format');
      }
    }

    // Ensure page exists
    const page = await this.pageService.upsertPage(pageSlug, projectId, {
      pageTitle: body.pageTitle,
      pageUrl: body.pageUrl,
    });

    const commentId = crypto.randomUUID();

    // Create comment (using validated, trimmed values)
    const result = await this.env.DB.prepare(`
      INSERT INTO comments (id, page_id, content, by_email, by_nickname, parent_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `).bind(
      commentId,
      page.id,
      content,
      email || null,
      nickname,
      parentId || null
    ).run();

    if (!result.success) {
      throw new Error('Failed to create comment');
    }

    // Return DB-canonical property names so downstream consumers (notification
    // service, etc.) can read by_nickname/by_email consistently. Spreading
    // ...body would have leaked the request-side names (nickname/email).
    return {
      id: commentId,
      content,
      by_email: email || null,
      by_nickname: nickname,
      page_id: page.id,
      parent_id: parentId || null,
      approved: false,
      created_at: new Date().toISOString(),
    };
  }

  async addCommentAsModerator(parentId: string, content: string, moderatorId: string) {
    // Get parent comment to find page
    const parent = await this.env.DB.prepare(
      'SELECT page_id FROM comments WHERE id = ?'
    ).bind(parentId).first() as any;

    if (!parent) {
      throw new Error('Parent comment not found');
    }

    // Get moderator info
    const moderator = await this.env.DB.prepare(
      'SELECT email, name FROM users WHERE id = ?'
    ).bind(moderatorId).first() as any;

    if (!moderator) {
      throw new Error('Moderator not found');
    }

    const commentId = crypto.randomUUID();

    await this.env.DB.prepare(`
      INSERT INTO comments (
        id, page_id, content, by_email, by_nickname, 
        moderator_id, parent_id, approved, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
    `).bind(
      commentId,
      parent.page_id,
      content,
      moderator.email,
      moderator.name || 'Moderator',
      moderatorId,
      parentId
    ).run();

    return {
      id: commentId,
      content,
      by_email: moderator.email,
      by_nickname: moderator.name || 'Moderator',
      moderator_id: moderatorId,
      parent_id: parentId,
      approved: true,
      created_at: new Date().toISOString(),
    };
  }

  async approve(commentId: string) {
    await this.env.DB.prepare(
      'UPDATE comments SET approved = 1, updated_at = datetime(\'now\') WHERE id = ?'
    ).bind(commentId).run();
  }

  async delete(commentId: string) {
    await this.env.DB.prepare(
      'UPDATE comments SET deleted_at = datetime(\'now\'), updated_at = datetime(\'now\') WHERE id = ?'
    ).bind(commentId).run();
  }

  async getProject(commentId: string) {
    const result = await this.env.DB.prepare(`
      SELECT pr.id, pr.owner_id
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      WHERE c.id = ?
    `).bind(commentId).first() as any;

    if (!result) {
      throw new Error('Comment not found');
    }

    return {
      id: result.id,
      ownerId: result.owner_id,
    };
  }

  async getCommentForApproval(commentId: string) {
    const result = await this.env.DB.prepare(`
      SELECT 
        c.by_nickname, c.by_email, c.content, c.approved,
        p.title as page_title, p.slug as page_slug, p.url as page_url,
        pr.title as project_title
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      WHERE c.id = ? AND c.deleted_at IS NULL
    `).bind(commentId).first() as any;

    if (!result) {
      throw new Error('Comment not found');
    }

    return {
      by_nickname: result.by_nickname,
      by_email: result.by_email,
      content: result.content,
      approved: Boolean(result.approved),
      page: {
        title: result.page_title,
        slug: result.page_slug,
        url: result.page_url,
        project: {
          title: result.project_title
        }
      }
    };
  }
}