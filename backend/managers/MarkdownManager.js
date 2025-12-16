// Markdown Manager
// Handles markdown parsing and sanitization
//
// Permitted Markdown Elements
// bold, italics
//
// Permitted HTML Elements
// <p>, <br/> 

class MarkdownManager {
    static parseMarkdown = (markdownText) => {
        // Strip out any HTML tags for safety (leaving <p> and <br/>)
        const sanitizedText = markdownText
            .replace(/\n/g, '<br/>')                    // Convert newlines to <br/>
            .replace(/<(?!\/?(p|br)\b)[^>]*>/gi, '');   // Remove all tags except <p> and <br/>

        let htmlText = sanitizedText

        // Parse Bold
        htmlText = htmlText.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        htmlText = htmlText.replace(/__(.*?)__/g, '<strong>$1</strong>');

        // Parse Italics
        htmlText = htmlText.replace(/\*(.*?)\*/g, '<em>$1</em>');
        htmlText = htmlText.replace(/_(.*?)_/g, '<em>$1</em>');

        return htmlText;
    }
}

export default MarkdownManager;