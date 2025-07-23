import { Request } from 'express';

export interface UserRequest extends Request {
  user?: {
    sub: string;
    name: string;
    email: string;
  };
}
