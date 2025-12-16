// Email Manager
// Handles email sending functionalities
// Requires a .env file in this directory with email configuration

// .env file variables
// EMAIL_HOST=your_smtp_host
// EMAIL_PORT=your_smtp_port
// EMAIL_SECURE=true_or_false_based_on_your_smtp
// EMAIL_SENDER_EMAIL=your_email_address
// EMAIL_ACCOUNT_PASSWORD=your_email_password

// Imports
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

// I elected to use this approach to keep email credentials separate from other environment variables and contain email logic to folder
dotenv.config({path: './email/.env'});

class EmailManager {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_SENDER_EMAIL,
                pass: process.env.EMAIL_ACCOUNT_PASSWORD
            }
        })
    }

    // Sends an email
    async sendEmail (to, subject, emailContent) {
        this.transporter.sendMail({
            from: `"Comment Corner" <${process.env.EMAIL_SENDER_EMAIL}>`,
            to: to,
            subject: subject,
            html: emailContent,
        }).then(_ => {
            return true;
        }).catch(_ => {
            return false;
        });
        return { success: true, messageId: 'not-configured' };
    }
}

export default EmailManager;