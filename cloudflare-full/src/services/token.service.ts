import { sign, verify } from 'hono/jwt';
import { Env } from '../index';

export enum UnSubscribeType {
  NEW_COMMENT = 'NEW_COMMENT',
}

export enum SecretKey {
  ApproveComment = 'approve_comment',
  DeleteComment = 'delete_comment',
  Unsubscribe = 'unsubscribe',
  AcceptNotify = 'accept_notify'
}

export module TokenBody {
  export type AcceptNotifyToken = {
    commentId: string
  }

  export type ApproveComment = {
    commentId: string,
    ownerId: string
  }

  export type DeleteComment = {
    commentId: string,
    ownerId: string
  }

  export type UnsubscribeNewComment = {
    userId: string,
    type: UnSubscribeType
  }
}

export class TokenService {
  constructor(private env: Env) {}

  async validate(token: string, secretKey: string) {
    const result = await verify(token, `${this.env.JWT_SECRET}-${secretKey}`);
    return result;
  }

  async sign(secretKey: SecretKey, body: any, expiresInSeconds: number) {
    const payload = {
      ...body,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresInSeconds
    };
    
    return await sign(payload, `${this.env.JWT_SECRET}-${secretKey}`);
  }

  async genApproveToken(commentId: string) {
    // Get comment owner info
    const comment = await this.env.DB.prepare(`
      SELECT pr.owner_id
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      WHERE c.id = ?
    `).bind(commentId).first() as any;

    if (!comment) {
      throw new Error('Comment not found');
    }

    return this.sign(
      SecretKey.ApproveComment,
      {
        commentId,
        ownerId: comment.owner_id,
      } as TokenBody.ApproveComment,
      3 * 24 * 60 * 60 // 3 days
    );
  }

  genUnsubscribeNewCommentToken(userId: string) {
    return this.sign(
      SecretKey.Unsubscribe,
      {
        userId,
        type: UnSubscribeType.NEW_COMMENT,
      } as TokenBody.UnsubscribeNewComment,
      365 * 24 * 60 * 60 // 1 year
    );
  }

  genAcceptNotifyToken(commentId: string) {
    return this.sign(
      SecretKey.AcceptNotify,
      {
        commentId
      } as TokenBody.AcceptNotifyToken,
      24 * 60 * 60 // 1 day
    );
  }

  async validateAcceptNotifyToken(token: string) {
    return await this.validate(token, SecretKey.AcceptNotify) as TokenBody.AcceptNotifyToken;
  }

  async validateApproveToken(token: string) {
    return await this.validate(token, SecretKey.ApproveComment) as TokenBody.ApproveComment;
  }

  async genDeleteToken(commentId: string) {
    const comment = await this.env.DB.prepare(`
      SELECT pr.owner_id
      FROM comments c
      INNER JOIN pages p ON c.page_id = p.id
      INNER JOIN projects pr ON p.project_id = pr.id
      WHERE c.id = ?
    `).bind(commentId).first() as any;

    if (!comment) {
      throw new Error('Comment not found');
    }

    return this.sign(
      SecretKey.DeleteComment,
      {
        commentId,
        ownerId: comment.owner_id,
      } as TokenBody.DeleteComment,
      3 * 24 * 60 * 60 // 3 days
    );
  }

  async validateDeleteToken(token: string) {
    return await this.validate(token, SecretKey.DeleteComment) as TokenBody.DeleteComment;
  }

  async validateUnsubscribeToken(token: string) {
    return await this.validate(token, SecretKey.Unsubscribe) as TokenBody.UnsubscribeNewComment;
  }
}