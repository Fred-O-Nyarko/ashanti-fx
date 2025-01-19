import { User } from "@prisma/client";

export const removeSensitiveData = (user: Partial<User>) => {
    delete user.password
    return user
}