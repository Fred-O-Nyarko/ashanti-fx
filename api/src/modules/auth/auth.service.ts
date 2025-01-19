import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { LoginRequestDto } from '../dto/login.dto';
import { compareSync } from 'bcrypt'
import { User } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { removeSensitiveData } from 'src/common/utils';

@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService

    ) { }

    async login({ email, password }: LoginRequestDto): Promise<Partial<User>> {
        const user = await this.prisma.user.findUnique({ where: { email } })
        if (!user)
            throw new NotFoundException('Invalid credentials')

        const isPasswordValid = compareSync(password, user.password)
        if (!isPasswordValid)
            throw new UnauthorizedException('Invalid credentials')

        return removeSensitiveData(user)
    }

    async generateTokens(user: Partial<User>) {
        const JWT_SECRET = this.configService.getOrThrow<string>('JWT_SECRET')
        const ACCESSTOKEN_EXPIRATION_TIME = this.configService.getOrThrow<string>('ACCESS_TOKEN_EXPIRY')
        const REFRESH_TOKEN_SECRET = this.configService.getOrThrow<string>(
            'REFRESH_TOKEN_SECRET',
        );
        const REFRESH_TOKEN_EXPIRATION_TIME = this.configService.getOrThrow<string>(
            'REFRESH_TOKEN_EXPIRY',
        );

        const payload = { id: user.id }

        const accessToken = this.jwtService.sign(payload, { secret: JWT_SECRET, expiresIn: ACCESSTOKEN_EXPIRATION_TIME })
        const refreshToken = this.jwtService.sign(payload, { secret: REFRESH_TOKEN_SECRET, expiresIn: REFRESH_TOKEN_EXPIRATION_TIME })

        return { accessToken, refreshToken }

    }
}
