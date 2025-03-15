import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'secret-key', // Thay bằng biến môi trường sau này
    });
  }

  async validate(payload: any) {
    console.log('Decoded JWT payload:', payload); // Debug log
    return { sub: String(payload.sub), email: payload.email }; // Chuyển thành string
  }
}
