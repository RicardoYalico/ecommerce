import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import prisma from "@/utils/db";
import { nanoid } from "nanoid";

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            id: "credentials",
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "text" },
                password: { label: "Password", type: "password" },
            },
            async authorize(credentials) {
                try {
                    const user = await prisma.user.findFirst({
                        where: { email: credentials?.email },
                    });

                    if (!user || !user.password) return null;

                    const isPasswordCorrect = await bcrypt.compare(
                        credentials!.password,
                        user.password
                    );

                    if (isPasswordCorrect) return user;
                    return null;
                } catch (err) {
                    console.error("Error in authorize:", err);
                    throw new Error("Authentication failed");
                }
            },
        }),
    ],
    callbacks: {
        async signIn({ user, account }) {
            return true;
        },
    },
};
