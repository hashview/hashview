from flask import Blueprint, jsonify
from hashview.models import TaskQueues

api = Blueprint('api', __name__)

@api.route('/v1/not_authorized', methods=['GET', 'POST'])
def api_unauthorized():
    message = {
        status: 200,
        type: 'Error',
        msg: 'Your agent is not authorized to work with this cluster.'
    }
    return jsonify(message)

@api.route('/v1/queue', methods=['GET'])
def api_queue():
    # TO DO CHECK IF AUTHORIZED
    queue = TaskQueues.query.filter_by(status = 'Queued').first()
    if queue:
        message = {
            # TODO
            status: 200,
            msg: 'todo'
        }
    else:
        message = {
            status: 200,
            type: 'Error',
            msg: 'There are no items on the queue to process'
        }
    return jsonify(message)