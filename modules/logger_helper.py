import logging
import os

def get_logger():
    """
    Initializes and returns a logger that writes debug messages to reports/output.log.
    Ensures the 'reports' folder exists and avoids adding duplicate handlers.
    """
    
    # Define the path to the log file
    log_file = os.path.join("reports", "output.log")
    
    # Create the reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)

    # Create a logger instance named 'WebShellAnalyzer'
    logger = logging.getLogger("WebShellAnalyzer")
    logger.setLevel(logging.DEBUG)  # Capture all levels (DEBUG and above)

    # Avoid adding multiple handlers if already configured
    if not logger.handlers:
        # Create a file handler that writes to output.log
        fh = logging.FileHandler(log_file, mode='w', encoding="utf-8")  # <-- mode='w' overwrites file
        fh.setLevel(logging.DEBUG)

        # Define log message format: timestamp - level - message
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)

        # Attach the file handler to the logger
        logger.addHandler(fh)

    # Return the configured logger instance
    return logger
