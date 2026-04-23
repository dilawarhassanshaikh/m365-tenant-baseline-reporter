'use client';

import * as React from 'react';
import {
  makeStyles,
  shorthands,
  Title1,
  Title3,
  Body1,
  Card,
  CardHeader,
  Button,
  Table,
  TableHeader,
  TableRow,
  TableHeaderCell,
  TableBody,
  TableCell,
  TableCellLayout,
  Badge,
  Divider,
} from '@fluentui/react-components';
import {
  CheckmarkCircleRegular,
  DismissCircleRegular,
  QuestionCircleRegular,
  DocumentDataRegular,
  DocumentPdfRegular,
  CodeRegular,
  LockClosedRegular,
} from '@fluentui/react-icons';
import { CONTROLS, scoreBaseline, BaselineResult } from '../lib/baseline/types';
import { MOCK_FINDINGS } from '../lib/baseline/mockData';
import { exportToJson, exportToHtml, exportToPdf } from '../lib/baseline/export';
import { AuthContext } from './providers';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('20px'),
    padding: '40px',
    maxWidth: '1200px',
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  summaryCards: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    ...shorthands.gap('16px'),
  },
  card: {
    ...shorthands.padding('16px'),
  },
  cardValue: {
    fontSize: '32px',
    fontWeight: 'bold',
    marginTop: '8px',
  },
  tableContainer: {
    marginTop: '20px',
  },
  actions: {
    display: 'flex',
    ...shorthands.gap('10px'),
    marginTop: '20px',
  },
  loginContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '80vh',
    ...shorthands.gap('20px'),
  },
  loginCard: {
    padding: '40px',
    width: '450px',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    textAlign: 'center',
    ...shorthands.gap('20px'),
  },
  microsoftButton: {
    backgroundColor: '#2f2f2f',
    color: 'white',
    ...shorthands.padding('10px', '20px'),
    '&:hover': {
      backgroundColor: '#3f3f3f',
      color: 'white',
    }
  }
});

export default function Dashboard() {
  const styles = useStyles();
  const { isAuthenticated, login, logout } = React.useContext(AuthContext);
  const [result, setResult] = React.useState<BaselineResult | null>(null);

  React.useEffect(() => {
    if (isAuthenticated) {
      const scored = scoreBaseline(CONTROLS, MOCK_FINDINGS);
      setResult(scored);
    }
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return (
      <div className={styles.loginContainer}>
        <Card className={styles.loginCard}>
          <LockClosedRegular style={{ fontSize: '64px', color: '#0078d4' }} />
          <Title1>Microsoft 365 Admin Sign In</Title1>
          <Body1>Sign in with your administrator account to access the Tenant Baseline Security Report.</Body1>
          <Button
            className={styles.microsoftButton}
            size="large"
            onClick={login}
            icon={<Image src="https://authjs.dev/img/providers/microsoft.svg" width={20} height={20} />}
          >
            Sign in with Microsoft
          </Button>
        </Card>
      </div>
    );
  }

  if (!result) return <Body1>Loading...</Body1>;

  const passCount = result.controls.filter(c => c.status === 'Pass').length;
  const failCount = result.controls.filter(c => c.status === 'Fail').length;
  const unknownCount = result.controls.filter(c => c.status === 'Unknown').length;

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'Pass':
        return <Badge appearance="filled" color="success" icon={<CheckmarkCircleRegular />}>Pass</Badge>;
      case 'Fail':
        return <Badge appearance="filled" color="danger" icon={<DismissCircleRegular />}>Fail</Badge>;
      default:
        return <Badge appearance="filled" color="informative" icon={<QuestionCircleRegular />}>Unknown</Badge>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'High': return <Badge appearance="outline" color="danger">High</Badge>;
      case 'Medium': return <Badge appearance="outline" color="important">Medium</Badge>;
      case 'Low': return <Badge appearance="outline" color="informative">Low</Badge>;
      default: return <Badge appearance="outline">Unknown</Badge>;
    }
  };

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <div>
          <Title1>M365 Tenant Baseline</Title1>
          <Body1 block style={{ color: 'gray', marginTop: '4px' }}>
            Tenant: <strong>{result.findings.organization.displayName}</strong> | Generated: {new Date(result.generatedAt).toLocaleString()}
          </Body1>
        </div>
        <div className={styles.actions}>
          <Button icon={<CodeRegular />} onClick={() => result && exportToJson(result)}>JSON</Button>
          <Button icon={<DocumentDataRegular />} onClick={() => result && exportToHtml(result)}>HTML</Button>
          <Button icon={<DocumentPdfRegular />} appearance="primary" onClick={() => result && exportToPdf(result)}>PDF</Button>
          <Button onClick={logout}>Sign Out</Button>
        </div>
      </header>

      <Divider />

      <section className={styles.summaryCards}>
        <Card className={styles.card}>
          <CardHeader header={<Body1>Overall Score</Body1>} />
          <div className={styles.cardValue}>{result.scorePercent}%</div>
        </Card>
        <Card className={styles.card}>
          <CardHeader header={<Body1>Passed</Body1>} />
          <div className={styles.cardValue} style={{ color: '#22c55e' }}>{passCount}</div>
        </Card>
        <Card className={styles.card}>
          <CardHeader header={<Body1>Failed</Body1>} />
          <div className={styles.cardValue} style={{ color: '#ef4444' }}>{failCount}</div>
        </Card>
        <Card className={styles.card}>
          <CardHeader header={<Body1>Unknown</Body1>} />
          <div className={styles.cardValue} style={{ color: '#94a3b8' }}>{unknownCount}</div>
        </Card>
        <Card className={styles.card}>
          <CardHeader header={<Body1>Total Controls</Body1>} />
          <div className={styles.cardValue}>{result.controls.length}</div>
        </Card>
      </section>

      <section className={styles.tableContainer}>
        <Title3>Control Results</Title3>
        <Table aria-label="Baseline controls table">
          <TableHeader>
            <TableRow>
              <TableHeaderCell>ID</TableHeaderCell>
              <TableHeaderCell>Title</TableHeaderCell>
              <TableHeaderCell>Category</TableHeaderCell>
              <TableHeaderCell>Severity</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>Recommendation</TableHeaderCell>
            </TableRow>
          </TableHeader>
          <TableBody>
            {result.controls.map((c) => (
              <TableRow key={c.id}>
                <TableCell>
                  <TableCellLayout>{c.id}</TableCellLayout>
                </TableCell>
                <TableCell>
                  <TableCellLayout><strong>{c.title}</strong></TableCellLayout>
                </TableCell>
                <TableCell>
                  <TableCellLayout>{c.category}</TableCellLayout>
                </TableCell>
                <TableCell>
                  <TableCellLayout>{getSeverityBadge(c.severity)}</TableCellLayout>
                </TableCell>
                <TableCell>
                  <TableCellLayout>{getStatusBadge(c.status)}</TableCellLayout>
                </TableCell>
                <TableCell>
                  <TableCellLayout>{c.recommendation}</TableCellLayout>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>
    </div>
  );
}
function Image({ src, width, height }: { src: string, width: number, height: number }) {
  return <img src={src} width={width} height={height} alt="" />;
}
