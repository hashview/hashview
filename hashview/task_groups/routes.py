from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from hashview.task_groups.forms import TaskGroupsForm
from hashview.models import Tasks, TaskGroups, Users, Jobs
from hashview import db
from hashview.utils.utils import get_keyspace
import json

task_groups = Blueprint('task_groups', __name__)

@task_groups.route("/task_groups", methods=['GET', 'POST'])
@login_required
def task_groups_list():
    task_groups = TaskGroups.query.all()
    tasks = Tasks.query.all()
    users = Users.query.all()

    return render_template('task_groups.html', title='Task Groups', task_groups=task_groups, users=users, tasks=tasks) 

@task_groups.route("/task_groups/add", methods=['GET', 'POST'])
@login_required
def task_groups_add():
    taskGroupsForm = TaskGroupsForm()
    tasks = Tasks.query
    emptyList = []
    if taskGroupsForm.validate_on_submit():
        task_group = TaskGroups(name=taskGroupsForm.name.data, owner_id=current_user.id, tasks=str(emptyList))
        db.session.add(task_group)
        db.session.commit()
        flash(f'Task {taskGroupsForm.name.data} created!', 'success')           
        # TODO change this redirect to use a url_for
        #return redirect(url_for('taskgroups.taskgroups_assigntask', taskgroup_id=taskgroup.id))  
        return redirect("assigned_tasks/"+str(task_group.id))
    return render_template('task_groups_add.html', title='Tasks Add', tasks=tasks, taskGroupsForm=taskGroupsForm)   

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>", methods=['GET', 'POST'])
@login_required
def task_groups_assigned_tasks(task_group_id):
    task_group = TaskGroups.query.get(task_group_id)
    tasks = Tasks.query
    task_group_tasks = json.loads(task_group.tasks)
    return render_template('task_groups_assigntask.html', title='Task Group: Assign Tasks', task_group=task_group, tasks=tasks, task_group_tasks=task_group_tasks)

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/add_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_add_task(task_group_id, task_id):
    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    task_group_tasks.append(task_id)
    task_group.tasks = str(task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/remove_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_remove_task(task_group_id, task_id):
    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    task_group_tasks.remove(task_id)
    task_group.tasks = str(task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/promote_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_promote_task(task_group_id, task_id):
    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    if task_group_tasks[0] == task_id:
        # Cant promote further
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    else:
        new_task_group_tasks = []
        # Creating manual index since for loop doesnt allow you to modify the itterator value
        index = 0
        while index < len(task_group_tasks):
            if index+1 < len(task_group_tasks):
                if task_group_tasks[index+1] == task_id:
                    new_task_group_tasks.append(task_id)
                    new_task_group_tasks.append(task_group_tasks[index])
                    index = index + 1
                else:
                    new_task_group_tasks.append(task_group_tasks[index])
            else:
                new_task_group_tasks.append(task_group_tasks[index])
            index+=1
    task_group.tasks = str(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/assigned_tasks/<int:task_group_id>/demote_task/<int:task_id>", methods=['GET'])
@login_required
def task_groups_assigned_tasks_demote_task(task_group_id, task_id):
    task_group = TaskGroups.query.get(task_group_id)
    task_group_tasks = json.loads(task_group.tasks)
    if task_group_tasks[-1] == task_id:
        # Cant demote further
        return redirect("/task_groups/assigned_tasks/"+str(task_group.id))
    else:
        new_task_group_tasks = []
        # Creating manual index since for loop doesnt allow you to modify the itterator value
        index = 0
        while index < len(task_group_tasks):
            if index+1 < len(task_group_tasks):
                if task_group_tasks[index] == task_id:
                    new_task_group_tasks.append(task_group_tasks[index+1])
                    new_task_group_tasks.append(task_id)
                    index = index + 1
                else:
                    new_task_group_tasks.append(task_group_tasks[index])
            else:
                new_task_group_tasks.append(task_group_tasks[index])
            index+=1
    task_group.tasks = str(new_task_group_tasks)
    db.session.commit()
    return redirect("/task_groups/assigned_tasks/"+str(task_group.id))

@task_groups.route("/task_groups/delete/<int:task_group_id>", methods=['POST'])
@login_required
def task_groups_delete(task_group_id):
    task_group = TaskGroups.query.get(task_group_id)
    if current_user.admin or task_group.owner_id == current_user.id:
        db.session.delete(task_group)
        db.session.commit()
        flash('Task Group has been deleted!', 'success')
        return redirect(url_for('task_groups.task_groups_list'))
    else:
        abort(403)