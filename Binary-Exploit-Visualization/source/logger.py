import logging.config
import structlog
from structlog import configure, processors, stdlib, threadlocal
from pythonjsonlogger import jsonlogger
import sys


def get_logger(name):
    Fhandler = logging.FileHandler("analysis.log")
    Fhandler.setFormatter(jsonlogger.JsonFormatter("%(message)s %(name)s"))
    Fhandler.setLevel(level=logging.DEBUG)

    # Chandler = logging.StreamHandler(sys.stdout)
    # Chandler.setLevel(level=logging.INFO)

    # C_filter = logging.Filter()
    # C_filter.filter = lambda record : record.levelno >= logging.WARNING

    # Chandler.addFilter(C_filter)

    root_logger = logging.getLogger(name)
    root_logger.addHandler(Fhandler)
    # root_logger.addHandler(Chandler)
    root_logger.setLevel(level=logging.DEBUG)

    struct_logger = structlog.wrap_logger(
        root_logger,
        context_class=threadlocal.wrap_dict(dict),
        logger_factory=stdlib.LoggerFactory(),
        wrapper_class=stdlib.BoundLogger,
        processors=[
            stdlib.filter_by_level,
            stdlib.add_logger_name,
            stdlib.add_log_level,
            stdlib.PositionalArgumentsFormatter(),
            processors.TimeStamper(fmt="iso"),
            processors.StackInfoRenderer(),
            processors.format_exc_info,
            processors.UnicodeDecoder(),
            stdlib.render_to_log_kwargs]
    )
    return struct_logger