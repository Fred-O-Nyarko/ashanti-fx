import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginRequestDto } from '../dto/login.dto';
import { Response, Request } from 'express';
import ms from 'ms';
import { IS_DEV } from 'src/common/constants';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {

  }

  @Post('login')
  public async login(@Body() body: LoginRequestDto, @Res({ passthrough: true }) res: Response) {
    const response = await this.authService.login(body)

    const { accessToken, refreshToken } = await this.authService.generateTokens(response)

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: !IS_DEV,
      sameSite: 'strict',
      maxAge: ms('15m'),
      priority: 'high'
    })

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: !IS_DEV,
      sameSite: 'strict',
      maxAge: ms('7d'),
      priority: 'high',
    })

    return {
      success: true,
      message: 'Login successful'
    }

  }
}
