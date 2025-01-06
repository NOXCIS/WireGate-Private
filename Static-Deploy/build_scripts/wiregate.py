# Copyright(C) 2025 NOXCIS [https://github.com/NOXCIS]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from wiregate.dashboard import waitressInit, startThreads, get_timestamped_filename, RotatingFileHandler, logging
from wiregate.dashboard import app, app_ip, app_port
import waitress



if __name__ == "__main__":
   
    waitressInit()
    # Start background threads
    startThreads()

    # Initialize logger 
    # Set up the rotating file handler with dynamic filename
    log_filename = get_timestamped_filename()
    handler = RotatingFileHandler(log_filename, maxBytes=1000000, backupCount=3)

    logger = logging.getLogger('wiregate')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)


    # Start the Waitress server with access logging enabled
    waitress.serve(
        app,
        host=app_ip,
        port=app_port,
        threads=8,
        _quiet=False,  # Ensures Waitress uses the 'waitress.access' logger for requests
    )