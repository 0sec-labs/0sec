import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export function EvidenceTabs({
  request,
  response,
  analysis,
}: {
  request: string;
  response: string;
  analysis?: string | null;
}) {
  return (
    <Tabs defaultValue="request" className="space-y-4">
      <TabsList>
        {[
          ["request", "Evidence request"],
          ["response", "Evidence response"],
          ["analysis", "Analysis"],
        ].map(([value, label]) => (
          <TabsTrigger key={value} value={value}>
            {label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value="request">
        <Card>
          <CardContent className="p-4">
            <pre className="text-sm leading-6 text-muted-foreground">{request}</pre>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="response">
        <Card>
          <CardContent className="p-4">
            <pre className="text-sm leading-6 text-muted-foreground">{response}</pre>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="analysis">
        <Card>
          <CardContent className="p-4">
            <pre className="text-sm leading-6 text-muted-foreground">{analysis ?? "No evidence analysis recorded."}</pre>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
