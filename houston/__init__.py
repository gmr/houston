"""
Houston
=======

Easy docker stack deployment to CoreOS clusters using Fleet and Consul

"""
__version__ = '0.3.0'


DEBUG_CONFIG = {
    'version': 1,
    'disable_existing_loggers': True,
    'incremental': False,
    'formatters': {
        'console': {
            'format': (
                '%(levelname)-8s %(name) -30s %(message)s'
            )
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
    },
    'loggers': {
        'consulate': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'fleetpy': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'houston': {
            'handlers': ['console'],
            'level': 'DEBUG',
        }
    }
}


LOG_CONFIG = {
    'version': 1,
    'disable_existing_loggers': True,
    'incremental': False,
    'formatters': {
        'console': {
            'format': (
                '%(levelname)-8s %(message)s'
            )
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
    },
    'loggers': {
        'consulate': {
            'handlers': ['console'],
            'level': 'WARNING',
        },
        'fleetpy': {
            'handlers': ['console'],
            'level': 'WARNING',
        },
        'houston': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    }
}
