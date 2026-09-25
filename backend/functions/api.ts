import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import {
  extractAuthContext,
  requirePermission,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(client);
const tableName = process.env.MAIN_TABLE || 'DailyReportSystem';

interface User {
  pk: string;
  sk: string;
  userId: string;
  userName: string;
  email: string;
  fullName: string;
  department?: string;
  role: string;
  status: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface Report {
  pk: string;
  sk: string;
  reportId: string;
  userId: string;
  reportDate: number;
  content: string;
  achievements?: string;
  issues?: string;
  nextPlan?: string;
  status: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface ReportItem {
  pk: string;
  sk: string;
  itemId: string;
  reportId: string;
  itemName: string;
  itemValue: string;
  itemOrder: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}

interface AuditLog {
  pk: string;
  sk: string;
  action: string;
  entityType: string;
  entityId: string;
  userId: string;
  changes: Record<string, unknown>;
  timestamp: number;
}

function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validateUser(user: Partial<User>): void {
  if (!user.userName || user.userName.length === 0) {
    throw new ValidationError('userName is required');
  }
  if (!user.email || !validateEmail(user.email)) {
    throw new ValidationError('Valid email is required');
  }
  if (!user.fullName || user.fullName.length === 0) {
    throw new ValidationError('fullName is required');
  }
  if (!user.role || !['admin', 'operator', 'viewer'].includes(user.role)) {
    throw new ValidationError('Valid role is required');
  }
  if (!user.status || !['active', 'inactive', 'suspended'].includes(user.status)) {
    throw new ValidationError('Valid status is required');
  }
}

function validateReport(report: Partial<Report>): void {
  if (!report.userId || report.userId.length === 0) {
    throw new ValidationError('userId is required');
  }
  if (!report.reportDate || report.reportDate <= 0) {
    throw new ValidationError('Valid reportDate is required');
  }
  if (!report.content || report.content.length === 0) {
    throw new ValidationError('content is required');
  }
  if (!report.status || !['draft', 'submitted', 'approved'].includes(report.status)) {
    throw new ValidationError('Valid status is required');
  }
}

function validateReportItem(item: Partial<ReportItem>): void {
  if (!item.reportId || item.reportId.length === 0) {
    throw new ValidationError('reportId is required');
  }
  if (!item.itemName || item.itemName.length === 0) {
    throw new ValidationError('itemName is required');
  }
  if (!item.itemValue || item.itemValue.length === 0) {
    throw new ValidationError('itemValue is required');
  }
  if (item.itemOrder === undefined || item.itemOrder < 0) {
    throw new ValidationError('Valid itemOrder is required');
  }
}

async function createAuditLog(
  action: string,
  entityType: string,
  entityId: string,
  userId: string,
  changes: Record<string, unknown>
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    action,
    entityType,
    entityId,
    userId,
    changes,
    timestamp: Date.now(),
  };

  await docClient.send(
    new PutCommand({
      TableName: tableName,
      Item: auditLog,
    })
  );
}

// GET /resources - List all resources
export async function getResources(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'users:read');

    const result = await docClient.send(
      new ScanCommand({
        TableName: tableName,
        FilterExpression: 'attribute_exists(pk) AND pk <> :auditPk',
        ExpressionAttributeValues: {
          ':auditPk': 'AUDIT',
        },
      })
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        items: result.Items || [],
        count: result.Count || 0,
      }),
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/users - Create user
export async function createUser(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'users:create');

    const body = JSON.parse(event.body || '{}');
    validateUser(body);

    const userId = randomUUID();
    const now = Date.now();
    const user: User = {
      pk: `USER#${userId}`,
      sk: `METADATA#${userId}`,
      userId,
      userName: body.userName,
      email: body.email,
      fullName: body.fullName,
      department: body.department,
      role: body.role,
      status: body.status,
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: user,
      })
    );

    await createAuditLog('CREATE', 'USER', userId, authContext.userId, { user });

    return {
      statusCode: 201,
      body: JSON.stringify(user),
    };
  } catch (error) {
    return handleError(error);
  }
}

// GET /api/users/{userId} - Get user by ID
export async function getUser(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'users:read');

    const userId = event.pathParameters?.userId;
    if (!userId) {
      throw new ValidationError('userId is required');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: `USER#${userId}`,
          sk: `METADATA#${userId}`,
        },
      })
    );

    if (!result.Item) {
      throw new NotFoundError('User not found');
    }

    return {
      statusCode: 200,
      body: JSON.stringify(result.Item),
    };
  } catch (error) {
    return handleError(error);
  }
}

// PUT /api/users/{userId} - Update user
export async function updateUser(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'users:update');

    const userId = event.pathParameters?.userId;
    if (!userId) {
      throw new ValidationError('userId is required');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const updateExpression = [];
    const expressionAttributeValues: Record<string, unknown> = {
      ':updatedAt': now,
      ':updatedBy': authContext.userId,
    };

    if (body.userName) {
      updateExpression.push('userName = :userName');
      expressionAttributeValues[':userName'] = body.userName;
    }
    if (body.email) {
      updateExpression.push('email = :email');
      expressionAttributeValues[':email'] = body.email;
    }
    if (body.fullName) {
      updateExpression.push('fullName = :fullName');
      expressionAttributeValues[':fullName'] = body.fullName;
    }
    if (body.department !== undefined) {
      updateExpression.push('department = :department');
      expressionAttributeValues[':department'] = body.department;
    }
    if (body.role) {
      updateExpression.push('#role = :role');
      expressionAttributeValues[':role'] = body.role;
    }
    if (body.status) {
      updateExpression.push('#status = :status');
      expressionAttributeValues[':status'] = body.status;
    }

    updateExpression.push('updatedAt = :updatedAt');

    const expressionAttributeNames: Record<string, string> = {};
    if (body.role) expressionAttributeNames['#role'] = 'role';
    if (body.status) expressionAttributeNames['#status'] = 'status';

    const result = await docClient.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          pk: `USER#${userId}`,
          sk: `METADATA#${userId}`,
        },
        UpdateExpression: `SET ${updateExpression.join(', ')}`,
        ExpressionAttributeValues: expressionAttributeValues,
        ...(Object.keys(expressionAttributeNames).length > 0 && {
          ExpressionAttributeNames: expressionAttributeNames,
        }),
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog('UPDATE', 'USER', userId, authContext.userId, body);

    return {
      statusCode: 200,
      body: JSON.stringify(result.Attributes),
    };
  } catch (error) {
    return handleError(error);
  }
}

// DELETE /api/users/{userId} - Delete user
export async function deleteUser(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'users:delete');

    const userId = event.pathParameters?.userId;
    if (!userId) {
      throw new ValidationError('userId is required');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: tableName,
        Key: {
          pk: `USER#${userId}`,
          sk: `METADATA#${userId}`,
        },
      })
    );

    await createAuditLog('DELETE', 'USER', userId, authContext.userId, {});

    return {
      statusCode: 204,
      body: '',
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/reports - Create report
export async function createReport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'reports:create');

    const body = JSON.parse(event.body || '{}');
    validateReport(body);

    const reportId = randomUUID();
    const now = Date.now();
    const report: Report = {
      pk: `REPORT#${reportId}`,
      sk: `METADATA#${reportId}`,
      reportId,
      userId: body.userId,
      reportDate: body.reportDate,
      content: body.content,
      achievements: body.achievements,
      issues: body.issues,
      nextPlan: body.nextPlan,
      status: body.status || 'draft',
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: report,
      })
    );

    await createAuditLog('CREATE', 'REPORT', reportId, authContext.userId, { report });

    return {
      statusCode: 201,
      body: JSON.stringify(report),
    };
  } catch (error) {
    return handleError(error);
  }
}

// GET /api/reports/{reportId} - Get report by ID
export async function getReport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'reports:read');

    const reportId = event.pathParameters?.reportId;
    if (!reportId) {
      throw new ValidationError('reportId is required');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT#${reportId}`,
          sk: `METADATA#${reportId}`,
        },
      })
    );

    if (!result.Item) {
      throw new NotFoundError('Report not found');
    }

    return {
      statusCode: 200,
      body: JSON.stringify(result.Item),
    };
  } catch (error) {
    return handleError(error);
  }
}

// PUT /api/reports/{reportId} - Update report
export async function updateReport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'reports:update');

    const reportId = event.pathParameters?.reportId;
    if (!reportId) {
      throw new ValidationError('reportId is required');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const updateExpression = [];
    const expressionAttributeValues: Record<string, unknown> = {
      ':updatedAt': now,
    };

    if (body.content) {
      updateExpression.push('content = :content');
      expressionAttributeValues[':content'] = body.content;
    }
    if (body.achievements !== undefined) {
      updateExpression.push('achievements = :achievements');
      expressionAttributeValues[':achievements'] = body.achievements;
    }
    if (body.issues !== undefined) {
      updateExpression.push('issues = :issues');
      expressionAttributeValues[':issues'] = body.issues;
    }
    if (body.nextPlan !== undefined) {
      updateExpression.push('nextPlan = :nextPlan');
      expressionAttributeValues[':nextPlan'] = body.nextPlan;
    }
    if (body.status) {
      updateExpression.push('#status = :status');
      expressionAttributeValues[':status'] = body.status;
    }

    updateExpression.push('updatedAt = :updatedAt');

    const expressionAttributeNames: Record<string, string> = {};
    if (body.status) expressionAttributeNames['#status'] = 'status';

    const result = await docClient.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT#${reportId}`,
          sk: `METADATA#${reportId}`,
        },
        UpdateExpression: `SET ${updateExpression.join(', ')}`,
        ExpressionAttributeValues: expressionAttributeValues,
        ...(Object.keys(expressionAttributeNames).length > 0 && {
          ExpressionAttributeNames: expressionAttributeNames,
        }),
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog('UPDATE', 'REPORT', reportId, authContext.userId, body);

    return {
      statusCode: 200,
      body: JSON.stringify(result.Attributes),
    };
  } catch (error) {
    return handleError(error);
  }
}

// DELETE /api/reports/{reportId} - Delete report
export async function deleteReport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'reports:delete');

    const reportId = event.pathParameters?.reportId;
    if (!reportId) {
      throw new ValidationError('reportId is required');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT#${reportId}`,
          sk: `METADATA#${reportId}`,
        },
      })
    );

    await createAuditLog('DELETE', 'REPORT', reportId, authContext.userId, {});

    return {
      statusCode: 204,
      body: '',
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/report-items - Create report item
export async function createReportItem(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'report_items:create');

    const body = JSON.parse(event.body || '{}');
    validateReportItem(body);

    const itemId = randomUUID();
    const now = Date.now();
    const reportItem: ReportItem = {
      pk: `REPORT_ITEM#${itemId}`,
      sk: `METADATA#${itemId}`,
      itemId,
      reportId: body.reportId,
      itemName: body.itemName,
      itemValue: body.itemValue,
      itemOrder: body.itemOrder,
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: tableName,
        Item: reportItem,
      })
    );

    await createAuditLog('CREATE', 'REPORT_ITEM', itemId, authContext.userId, {
      reportItem,
    });

    return {
      statusCode: 201,
      body: JSON.stringify(reportItem),
    };
  } catch (error) {
    return handleError(error);
  }
}

// GET /api/report-items/{itemId} - Get report item by ID
export async function getReportItem(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'report_items:read');

    const itemId = event.pathParameters?.itemId;
    if (!itemId) {
      throw new ValidationError('itemId is required');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT_ITEM#${itemId}`,
          sk: `METADATA#${itemId}`,
        },
      })
    );

    if (!result.Item) {
      throw new NotFoundError('Report item not found');
    }

    return {
      statusCode: 200,
      body: JSON.stringify(result.Item),
    };
  } catch (error) {
    return handleError(error);
  }
}

// PUT /api/report-items/{itemId} - Update report item
export async function updateReportItem(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'report_items:update');

    const itemId = event.pathParameters?.itemId;
    if (!itemId) {
      throw new ValidationError('itemId is required');
    }

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const updateExpression = [];
    const expressionAttributeValues: Record<string, unknown> = {
      ':updatedAt': now,
    };

    if (body.itemName) {
      updateExpression.push('itemName = :itemName');
      expressionAttributeValues[':itemName'] = body.itemName;
    }
    if (body.itemValue) {
      updateExpression.push('itemValue = :itemValue');
      expressionAttributeValues[':itemValue'] = body.itemValue;
    }
    if (body.itemOrder !== undefined) {
      updateExpression.push('itemOrder = :itemOrder');
      expressionAttributeValues[':itemOrder'] = body.itemOrder;
    }

    updateExpression.push('updatedAt = :updatedAt');

    const result = await docClient.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT_ITEM#${itemId}`,
          sk: `METADATA#${itemId}`,
        },
        UpdateExpression: `SET ${updateExpression.join(', ')}`,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog('UPDATE', 'REPORT_ITEM', itemId, authContext.userId, body);

    return {
      statusCode: 200,
      body: JSON.stringify(result.Attributes),
    };
  } catch (error) {
    return handleError(error);
  }
}

// DELETE /api/report-items/{itemId} - Delete report item
export async function deleteReportItem(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'report_items:delete');

    const itemId = event.pathParameters?.itemId;
    if (!itemId) {
      throw new ValidationError('itemId is required');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: tableName,
        Key: {
          pk: `REPORT_ITEM#${itemId}`,
          sk: `METADATA#${itemId}`,
        },
      })
    );

    await createAuditLog('DELETE', 'REPORT_ITEM', itemId, authContext.userId, {});

    return {
      statusCode: 204,
      body: '',
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/users/bulk - Bulk import users
export async function bulkImportUsers(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'bulk:import');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      throw new ValidationError('items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      const userId = randomUUID();
      return {
        pk: `USER#${userId}`,
        sk: `METADATA#${userId}`,
        userId,
        userName: item.userName,
        email: item.email,
        fullName: item.fullName,
        department: item.department,
        role: item.role || 'viewer',
        status: item.status || 'active',
        createdAt: now,
        updatedAt: now,
        createdBy: authContext.userId,
      };
    });

    const result = await batchWrite(processedItems);

    await createAuditLog('BULK_IMPORT', 'USER', 'BATCH', authContext.userId, {
      count: result.imported,
      failed: result.failed,
    });

    return {
      statusCode: 200,
      body: JSON.stringify(result),
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/reports/bulk - Bulk import reports
export async function bulkImportReports(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'bulk:import');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      throw new ValidationError('items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      const reportId = randomUUID();
      return {
        pk: `REPORT#${reportId}`,
        sk: `METADATA#${reportId}`,
        reportId,
        userId: item.userId,
        reportDate: item.reportDate || now,
        content: item.content,
        achievements: item.achievements,
        issues: item.issues,
        nextPlan: item.nextPlan,
        status: item.status || 'draft',
        createdAt: now,
        updatedAt: now,
        createdBy: authContext.userId,
      };
    });

    const result = await batchWrite(processedItems);

    await createAuditLog('BULK_IMPORT', 'REPORT', 'BATCH', authContext.userId, {
      count: result.imported,
      failed: result.failed,
    });

    return {
      statusCode: 200,
      body: JSON.stringify(result),
    };
  } catch (error) {
    return handleError(error);
  }
}

// POST /api/report-items/bulk - Bulk import report items
export async function bulkImportReportItems(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'bulk:import');

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items)) {
      throw new ValidationError('items must be an array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => {
      const itemId = randomUUID();
      return {
        pk: `REPORT_ITEM#${itemId}`,
        sk: `METADATA#${itemId}`,
        itemId,
        reportId: item.reportId,
        itemName: item.itemName,
        itemValue: item.itemValue,
        itemOrder: item.itemOrder || 0,
        createdAt: now,
        updatedAt: now,
        createdBy: authContext.userId,
      };
    });

    const result = await batchWrite(processedItems);

    await createAuditLog('BULK_IMPORT', 'REPORT_ITEM', 'BATCH', authContext.userId, {
      count: result.imported,
      failed: result.failed,
    });

    return {
      statusCode: 200,
      body: JSON.stringify(result),
    };
  } catch (error) {
    return handleError(error);
  }
}

async function batchWrite(
  items: Record<string, unknown>[]
): Promise<{ imported: number; failed: number; errors: string[] }> {
  const errors: string[] = [];
  let imported = 0;
  let failed = 0;

  // Split items into chunks of 25 (DynamoDB BatchWriteItem limit)
  const chunks = [];
  for (let i = 0; i < items.length; i += 25) {
    chunks.push(items.slice(i, i + 25));
  }

  for (const chunk of chunks) {
    const requestItems: BatchWriteItemCommandInput['RequestItems'] = {
      [tableName]: chunk.map((item) => ({
        PutRequest: {
          Item: item,
        },
      })),
    };

    try {
      const response = await client.send(
        new BatchWriteItemCommand({
          RequestItems: requestItems,
        })
      );

      imported += chunk.length - (response.UnprocessedItems?.[tableName]?.length || 0);
      failed += response.UnprocessedItems?.[tableName]?.length || 0;

      if (response.UnprocessedItems?.[tableName]?.length) {
        errors.push(
          `${response.UnprocessedItems[tableName].length} items failed to write in batch`
        );
      }
    } catch (error) {
      failed += chunk.length;
      errors.push(`Batch write failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return { imported, failed, errors };
}

function handleError(error: unknown): APIGatewayProxyResult {
  if (error instanceof ValidationError) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: error.message }),
    };
  }

  if (error instanceof ForbiddenError) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: error.message }),
    };
  }

  if (error instanceof NotFoundError) {
    return {
      statusCode: 404,
      body: JSON.stringify({ error: error.message }),
    };
  }

  console.error('Unhandled error:', error);
  return {
    statusCode: 500,
    body: JSON.stringify({
      error: 'Internal server error',
      message: error instanceof Error ? error.message : String(error),
    }),
  };
}