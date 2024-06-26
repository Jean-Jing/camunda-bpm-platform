/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.bpm.engine.impl.cmd;

import static org.camunda.bpm.engine.impl.util.EnsureUtil.ensureNotNull;

import java.io.Serializable;
import java.util.List;
import org.camunda.bpm.engine.ProcessEngineException;
import org.camunda.bpm.engine.history.UserOperationLogEntry;
import org.camunda.bpm.engine.impl.cfg.CommandChecker;
import org.camunda.bpm.engine.impl.interceptor.Command;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;
import org.camunda.bpm.engine.impl.persistence.entity.CommentEntity;
import org.camunda.bpm.engine.impl.persistence.entity.PropertyChange;
import org.camunda.bpm.engine.impl.persistence.entity.TaskEntity;
import org.camunda.bpm.engine.task.Comment;

/**
 * Command to delete a comment by a given commentId and taskId or to delete all comments
 * of a given task Id
 */

public class DeleteTaskCommentCmd implements Command<Object>, Serializable {

  private static final long serialVersionUID = 1L;
  protected String commentId;
  protected String taskId;

  public DeleteTaskCommentCmd(String taskId, String commentId) {
    this.taskId = taskId;
    this.commentId = commentId;
  }

  public DeleteTaskCommentCmd(String taskId) {
    this.taskId = taskId;
  }

  public Object execute(CommandContext commandContext) {
    if (commentId == null && taskId == null) {
      throw new ProcessEngineException("Both task and comment ids are null");
    }

    ensureNotNull("taskId", taskId);

    TaskEntity task = null;
    CommentEntity comment = null;
    if (commentId != null && taskId != null) {
      comment = commandContext.getCommentManager().findCommentByTaskIdAndCommentId(taskId, commentId);
      if (comment != null) {
        task = getTask(comment, commandContext);
        checkTaskAssign(task, commandContext);
        commandContext.getDbEntityManager().delete(comment);
      }
    } else {
      task = commandContext.getTaskManager().findTaskById(taskId);
      ensureNotNull("No task exists with taskId: " + taskId, "task", task);
      List<Comment> comments = commandContext.getCommentManager().findCommentsByTaskId(taskId);
      if (!comments.isEmpty()) {
        checkTaskAssign(task, commandContext);
        commandContext.getCommentManager().deleteCommentsByTaskId(taskId);
      }
    }

    if (task != null) {
      commandContext.getOperationLogManager()
          .logCommentOperation(UserOperationLogEntry.OPERATION_TYPE_DELETE_COMMENT, task,
              getCommentPropertyChange(comment != null ? comment.getMessage() : null));
      task.triggerUpdateEvent();
    }

    return null;
  }

  private PropertyChange getCommentPropertyChange(String message) {
    return new PropertyChange("comment", null, message);
  }

  private TaskEntity getTask(CommentEntity comment, CommandContext commandContext) {
    String taskId = comment.getTaskId();
    TaskEntity task = commandContext.getTaskManager().findTaskById(taskId);
    ensureNotNull("Task not found for taskId: " + taskId + " CommentId: " + commentId, "comment", comment);
    return task;
  }

  protected void checkTaskAssign(TaskEntity task, CommandContext commandContext) {
    for (CommandChecker checker : commandContext.getProcessEngineConfiguration().getCommandCheckers()) {
      checker.checkTaskAssign(task);
    }
  }
}
